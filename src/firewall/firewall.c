/** netmill: firewall
2024, Simon Zolin */

#include <netmill.h>
#include <exe/shared.h>

static int fw_help()
{
	help_info_write(
"Ingress firewall\n\
    `netmill firewall` OPTIONS\n\
Options:\n\
  `interface` INDEX|NAME \n\
\n\
  `eth_proto` ip|ipv6|NUMBER\n\
  `ip_proto` icmp|udp|tcp|NUMBER\n\
  `l4_src_port` N\n\
  `l4_dst_port` N\n\
");
	return R_DONE;
}

#include <ffbase/args.h>
#include <ffsys/std.h>
#include <bpf/libbpf.h>
#include <firewall/data.h>
#include <xdp/libxdp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <util/util.h>

struct firewall_rule {
	uint	eth_proto;
	uint	ip_proto;
	uint	l4_src_port, l4_dst_port;
};

struct firewall_conf {
	uint	if_index;
	struct firewall_rule rule;
};

struct firewall {
	uint stop;
	struct xdp_program *prog;
	struct bpf_object *bpf_obj;
	struct bpf_map *map_rules;
	struct bpf_map *map_stats;

	struct firewall_conf *conf;
};
static struct firewall *fw;

static void fw_err(const char *func, int code)
{
	if (code)
		ffstdout_fmt("ERROR: %s: %E\n", func, -code);
	else
		ffstdout_fmt("ERROR: %s\n", func);
}

static int fw_attach()
{
	int e;
	struct bpf_object_open_opts opts = {
		.sz = sizeof(struct bpf_object_open_opts),
	};

	// if (!(fw->bpf_obj = bpf_object__open_file("nmlfw-xdp-ebpf.o", &opts))) {
	// 	err_func = "bpf_object__open_file";
	// 	goto err;
	// }

	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	xdp_opts.open_filename = "nmlfw-xdp-ebpf.o";
	xdp_opts.opts = &opts;

	if (!(fw->prog = xdp_program__create(&xdp_opts))) {
		fw_err("xdp_program__create", libxdp_get_error(fw->prog));
		return -1;
	}
	if ((e = xdp_program__attach(fw->prog, fw->conf->if_index, 0, 0))) {
		fw_err("xdp_program__attach", e);
		return -1;
	}

	fw->bpf_obj = xdp_program__bpf_obj(fw->prog);
	return 0;
}

static int fw_detach()
{
	int e;
	if ((e = xdp_program__detach(fw->prog, fw->conf->if_index, 0, 0))) {
		fw_err("xdp_program__attach", e);
		return -1;
	}
	return 0;
}

static int fw_rule_add(const struct firewall_rule *rule)
{
	infolog("Installing rule: eth:%xu  ip:%xu  l4src:%u  l4dst:%u"
		, rule->eth_proto, rule->ip_proto, rule->l4_src_port, rule->l4_dst_port);

	struct nml_fw_rule_key k = {};
	*(ushort*)k.eth_proto = ffint_be_cpu16(rule->eth_proto);
	k.ip_proto = rule->ip_proto;
	*(ushort*)k.l4_src_port = ffint_be_cpu16(rule->l4_src_port);
	*(ushort*)k.l4_dst_port = ffint_be_cpu16(rule->l4_dst_port);
	struct nml_fw_rule v = {};
	if (bpf_map__update_elem(fw->map_rules, &k, sizeof(k), &v, sizeof(v), 0)) {
		fw_err("bpf_map__update_elem", 0);
		return -1;
	}
	return 0;
}

static int fw_maps_init()
{
	if (!(fw->map_rules = bpf_object__find_map_by_name(fw->bpf_obj, "nml_fw_rule_map"))) {
		fw_err("bpf_object__find_map_by_name", 0);
		return -1;
	}

	if (fw_rule_add(&fw->conf->rule))
		return -1;

	if (!(fw->map_stats = bpf_object__find_map_by_name(fw->bpf_obj, "nml_fw_stats_map"))) {
		fw_err("bpf_object__find_map_by_name", 0);
		return -1;
	}

	// ffvec pin_dir = {};
	// ffvec_addfmt(&pin_dir, "/sys/fs/bpf/%s%Z", "");
	// if ((e = bpf_object__unpin_maps(o, pin_dir.ptr))) {
	// }

	// if ((e = bpf_object__pin_maps(o, pin_dir.ptr))) {
	// 	err_func = "bpf_object__pin_maps";
	// 	goto err;
	// }
	// ffvec_free(&pin_dir);
	return 0;
}

static void fw_cleanup()
{
	// if ((e = bpf_object__unpin_maps(o, pin_dir.ptr))) {
	// }

	fw_detach();
}

static int fw_stats_display()
{
	int e;
	uint ncpu = libbpf_num_possible_cpus();
	uint cap = ncpu * sizeof(struct nml_fw_stats);
	struct nml_fw_stats *stats = ffmem_alloc(cap);
	__u32 key = 0;
	if ((e = bpf_map__lookup_elem(fw->map_stats, &key, sizeof(key), stats, cap, 0))) {
		fw_err("bpf_map__lookup_elem", e);
		return -1;
	}

	for (uint i = 1;  i < ncpu;  i++) {
		stats->drop_by_rule += stats[i].drop_by_rule;
		stats->drop_invalid += stats[i].drop_invalid;
	}

	ffvec v = {};
	ffvec_addfmt(&v, "drop_by_rule:\t%,U\n", stats->drop_by_rule);
	ffvec_addfmt(&v, "drop_invalid:\t%,U\n", stats->drop_invalid);
	ffstdout_write(v.ptr, v.len);
	ffvec_free(&v);
	ffmem_free(stats);
	return 0;
}

static int fw_setup(struct firewall_conf *conf)
{
	fw = ffmem_new(struct firewall);
	fw->conf = conf;

	if (fw_attach()) goto err;
	if (fw_maps_init()) goto err;
	return 0;

err:
	return -1;
}

static int fw_run(struct firewall_conf *conf)
{
	while (!FFINT_READONCE(fw->stop)) {
		fw_stats_display();
		sleep(1);
	}
	return 0;
}

static void fw_stop()
{
	FFINT_WRITEONCE(fw->stop, 1);
}

static const job_if fw_job;

static int fw_conf_check(struct firewall_conf *c)
{
	if (!c->if_index) {
		errlog("Please specify interface");
		return R_BADVAL;
	}

	if (!c->rule.eth_proto || !c->rule.ip_proto) {
		errlog("Please specify eth_proto and ip_proto");
		return R_BADVAL;
	}

	if ((c->rule.l4_src_port || c->rule.l4_dst_port)
		&& !(c->rule.ip_proto == IPPROTO_UDP || c->rule.ip_proto == IPPROTO_TCP)) {
		errlog("l4_src_port and l4_dst_port are for UDP or TCP only");
		return R_BADVAL;
	}

	x->job = &fw_job;
	return 0;
}

static int fw_interface(struct firewall_conf *c, ffstr name)
{
	if (!ffstr_to_uint32(&name, &c->if_index))
		c->if_index = ffnetconf_if_index(name);
	if (c->if_index == 0)
		return R_BADVAL;
	return 0;
}

static int fw_eth_proto(struct firewall_conf *c, ffstr name)
{
	if (ffstr_eqz(&name, "ip"))
		c->rule.eth_proto = ETH_P_IP;
	else if (ffstr_eqz(&name, "ipv6"))
		c->rule.eth_proto = ETH_P_IPV6;
	else {
		uint n;
		if (!ffstr_to_uint32(&name, &n))
			return R_BADVAL;
		c->rule.eth_proto = n;
	}
	return 0;
}

static int fw_ip_proto(struct firewall_conf *c, ffstr name)
{
	if (ffstr_eqz(&name, "icmp"))
		c->rule.ip_proto = IPPROTO_ICMP;
	else if (ffstr_eqz(&name, "tcp"))
		c->rule.ip_proto = IPPROTO_TCP;
	else if (ffstr_eqz(&name, "udp"))
		c->rule.ip_proto = IPPROTO_UDP;
	else {
		uint n;
		if (!ffstr_to_uint32(&name, &n))
			return R_BADVAL;
		c->rule.ip_proto = n;
	}
	return 0;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct firewall_conf, m)
static const struct ffarg firewall_args[] = {
	{ "eth_proto",	'S',	fw_eth_proto },
	{ "help",		'1',	fw_help },
	{ "interface",	'S',	fw_interface },
	{ "ip_proto",	'S',	fw_ip_proto },
	{ "l4_dst_port",'u',	O(rule.l4_dst_port) },
	{ "l4_src_port",'u',	O(rule.l4_src_port) },
	{ "",			'1',	fw_conf_check },
	{}
};
#undef O

struct ffarg_ctx firewall_ctx()
{
	struct firewall_conf *fc = ffmem_new(struct firewall_conf);
	struct ffarg_ctx ax = { firewall_args, fc };
	return ax;
}

static const job_if fw_job = {
	.setup = fw_setup,
	.run = fw_run,
	.stop = fw_stop,
	.destroy = fw_cleanup,
};
