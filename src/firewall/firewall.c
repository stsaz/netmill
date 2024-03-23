/** netmill: firewall
2024, Simon Zolin */

#include <netmill.h>

const nml_exe *exe;

#define syserrlog(...) \
	exe->log(NULL, NML_LOG_SYSERR, "firewall", NULL, __VA_ARGS__)

#define errlog(...) \
	exe->log(NULL, NML_LOG_ERR, "firewall", NULL, __VA_ARGS__)

#define infolog(...) \
	exe->log(NULL, NML_LOG_INFO, "firewall", NULL, __VA_ARGS__)

#define verblog(...) \
do { \
	if (exe->log_level >= NML_LOG_VERBOSE) \
		exe->log(NULL, NML_LOG_VERBOSE, "firewall", NULL, __VA_ARGS__); \
} while (0)

#define dbglog(...) \
do { \
	if (exe->log_level >= NML_LOG_DEBUG) \
		exe->log(NULL, NML_LOG_DEBUG, "firewall", NULL, __VA_ARGS__); \
} while (0)

#define R_DONE  100
#define R_BADVAL  101

static int fw_help()
{
	exe->print(
"Ingress firewall\n\
    `netmill firewall` OPTIONS\n\
Options:\n\
  `interface` NAME\n\
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
#include <firewall/data.h>
#include <util/util.h>
#include <util/lxdp.h>
#include <util/ethernet.h>
#include <util/ipaddr.h>

#define RX_BURST_SIZE  128

struct firewall_rule {
	uint	eth_proto;
	uint	ip_proto;
	uint	l4_src_port, l4_dst_port;
};

struct firewall_conf {
	uint	if_index;
	const char *if_name;
	const char *obj_filename;
	struct firewall_rule rule;
};

struct firewall {
	uint stop;

	lxdp lx;
	struct bpf_map *map_rules;
	struct bpf_map *map_stats;
	struct bpf_map *map_xsk;
	lxdpsk lxsk;

	lxdpbuf* packets[RX_BURST_SIZE];

	struct firewall_conf conf;
};

static int fw_attach(struct firewall *fw)
{
	struct lxdp_attach_conf conf = {};
	if (lxdp_attach(&fw->lx, fw->conf.obj_filename, fw->conf.if_index, &conf)) {
		errlog("lxdp_attach: %s", lxdp_error(&fw->lx));
		return -1;
	}
	return 0;
}

static int fw_detach(struct firewall *fw)
{
	lxdp_close(&fw->lx);
	return 0;
}

static int fw_xsk_init(struct firewall *fw)
{
	struct lxdpsk_conf conf = {};
	if (lxdpsk_create(&fw->lx, &fw->lxsk, fw->conf.if_name, 0, &conf)) {
		errlog("lxdpsk_create: %s", lxdp_error(&fw->lx));
		return -1;
	}
	if (lxdpsk_enable(&fw->lxsk, fw->map_xsk)) {
		errlog("lxdpsk_enable: %s", lxdp_error(&fw->lx));
		return -1;
	}
	return 0;
}

static int fw_rule_add(struct firewall *fw, const struct firewall_rule *rule)
{
	verblog("Installing rule: eth:%04xu  ip:%xu  l4src:%u  l4dst:%u"
		, rule->eth_proto, rule->ip_proto, rule->l4_src_port, rule->l4_dst_port);

	struct nml_fw_rule_key k = {};
	*(ushort*)k.eth_proto = ffint_be_cpu16(rule->eth_proto);
	k.ip_proto = rule->ip_proto;
	*(ushort*)k.l4_src_port = ffint_be_cpu16(rule->l4_src_port);
	*(ushort*)k.l4_dst_port = ffint_be_cpu16(rule->l4_dst_port);
	struct nml_fw_rule v = {};
	if (bpf_map__update_elem(fw->map_rules, &k, sizeof(k), &v, sizeof(v), 0)) {
		errlog("bpf_map__update_elem");
		return -1;
	}
	return 0;
}

static int fw_maps_init(struct firewall *fw)
{
	static const struct lxdp_map_name maps[] = {
		{ "nml_fw_rule_map",	FF_OFF(struct firewall, map_rules) },
		{ "nml_fw_stats_map",	FF_OFF(struct firewall, map_stats) },
		{ "nml_fw_xsk_map",		FF_OFF(struct firewall, map_xsk) },
		{}
	};
	if (lxdp_maps_link(&fw->lx, maps, fw)) {
		errlog("lxdp_maps_link", lxdp_error(&fw->lx));
		return -1;
	}

	if (fw_rule_add(fw, &fw->conf.rule))
		return -1;

	return 0;
}

static void fw_cleanup(struct firewall *fw)
{
	fw_detach(fw);
}

static int fw_stats_display(struct firewall *fw)
{
	int e;
	uint ncpu = libbpf_num_possible_cpus();
	uint cap = ncpu * sizeof(struct nml_fw_stats);
	struct nml_fw_stats *stats = ffmem_alloc(cap);
	__u32 key = 0;
	if ((e = bpf_map__lookup_elem(fw->map_stats, &key, sizeof(key), stats, cap, 0))) {
		errlog("bpf_map__lookup_elem: %E", -e);
		return -1;
	}

	for (uint i = 1;  i < ncpu;  i++) {
		stats->invalid += stats[i].invalid;
	}

	ffvec v = {};
	ffvec_addfmt(&v, "invalid:\t%,U\n", stats->invalid);
	ffstdout_write(v.ptr, v.len);
	ffvec_free(&v);
	ffmem_free(stats);
	return 0;
}

static int fw_setup(struct firewall *fw)
{
	if (fw_attach(fw)) goto err;
	if (fw_maps_init(fw)) goto err;
	if (fw_xsk_init(fw)) goto err;
	return 0;

err:
	return -1;
}

static int fw_pkt(struct firewall *fw, lxdpbuf *p)
{
	const void *data = lxdpbuf_data(p);

	char buf[1024];
	uint len = eth_hdr_str(data, buf, sizeof(buf));

	data += sizeof(struct eth_hdr);
	p->off_ip = sizeof(struct eth_hdr);
	lxdpbuf_shift(p, sizeof(struct eth_hdr));
	const struct ffip4_hdr *ip = data;

	buf[len++] = ' ';
	buf[len++] = ' ';
	len += ffip4_hdr_str(ip, buf + len, sizeof(buf) - len);
	infolog("input: %*s", (size_t)len, buf);

	return -1;
}

static void fw_process(struct firewall *fw)
{
	for (;;) {
		uint n = lxdpsk_read(&fw->lxsk, fw->packets, RX_BURST_SIZE);
		if (!n)
			break;

		for (uint i = 0;  i < n;  i++) {
			lxdpbuf *p = fw->packets[i];
			if (!fw_pkt(fw, p)) {
				lxdpsk_write(&fw->lxsk, &p, 1);
				dbglog("lxdpsk_write");
			} else {
				lxdpsk_buf_release(&fw->lxsk, p);
			}
		}
	}

	lxdpsk_flush(&fw->lxsk);
}

static int fw_run(struct firewall *fw)
{
	ffkq kq = ffkq_create();
	if (ffkq_attach(kq, lxdpsk_fd(&fw->lxsk), NULL, FFKQ_READ)) {
		syserrlog("ffkq_attach");
		return -1;
	}

	ffkq_time t;
	ffkq_time_set(&t, -1);
	ffkq_event events[1];
	while (!FFINT_READONCE(fw->stop)) {
		int r = ffkq_wait(kq, events, 1, t);
		if (r < 0) {
			if (errno != EINTR)
				syserrlog("ffkq_wait");
			break;
		}
		// dbglog("ffkq_wait");
		if (r > 0)
			fw_process(fw);
		if (0)
			fw_stats_display(fw);
		// sleep(1);
	}
	return 0;
}

static void fw_stop(struct firewall *fw)
{
	FFINT_WRITEONCE(fw->stop, 1);
}

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
		&& !(c->rule.ip_proto == FFIP_UDP || c->rule.ip_proto == FFIP_TCP)) {
		errlog("l4_src_port and l4_dst_port are for UDP or TCP only");
		return R_BADVAL;
	}

	return 0;
}

static int fw_interface(struct firewall_conf *c, ffstr name)
{
	// if (!ffstr_to_uint32(&name, &c->if_index))
	c->if_index = ffnetconf_if_index(name);
	if (c->if_index == 0)
		return R_BADVAL;
	c->if_name = ffsz_dupstr(&name);
	return 0;
}

static int fw_eth_proto(struct firewall_conf *c, ffstr name)
{
	if (ffstr_ieqz(&name, "ip"))
		c->rule.eth_proto = ETH_IP4;
	else if (ffstr_ieqz(&name, "ipv6"))
		c->rule.eth_proto = ETH_IP6;
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
	if (ffstr_ieqz(&name, "icmp"))
		c->rule.ip_proto = FFIP_ICMP;
	else if (ffstr_ieqz(&name, "tcp"))
		c->rule.ip_proto = FFIP_TCP;
	else if (ffstr_ieqz(&name, "udp"))
		c->rule.ip_proto = FFIP_UDP;
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

static nml_op* fw_create(char **argv)
{
	struct firewall *fw = ffmem_new(struct firewall);

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, firewall_args, &fw->conf, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
		{}
		else if (r == R_BADVAL)
			errlog("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			errlog("command line: %s\n", as.error);
		return NULL;
	}

	fw->conf.obj_filename = exe->path("mod/nmlfw-xdp-ebpf.o");
	return fw;
}

static void fw_close(nml_op *op)
{
	fw_cleanup(op);
}

static void _fw_run(nml_op *op)
{
	if (fw_setup(op)) return;
	fw_run(op);
}

static void fw_signal(nml_op *op, uint signal)
{
	fw_stop(op);
}

static const struct nml_operation_if nml_op_fw = {
	fw_create,
	fw_close,
	_fw_run,
	fw_signal,
};


static void fw_init(const nml_exe *x)
{
	exe = x;
}

static void fw_destroy()
{
}

extern const struct nml_operation_if nml_op_ping;

static const void* fw_provide(const char *name)
{
	if (ffsz_eq(name, "firewall"))
		return &nml_op_fw;
	if (ffsz_eq(name, "ping"))
		return &nml_op_ping;
	return NULL;
}

NML_MOD_DEFINE(fw);
