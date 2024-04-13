/** netmill: firewall
2024, Simon Zolin */

#include <netmill.h>

const nml_exe *exe;

#define SYSERR(...) \
	exe->log(NULL, NML_LOG_SYSERR, "firewall", NULL, __VA_ARGS__)

#define ERR(...) \
	exe->log(NULL, NML_LOG_ERR, "firewall", NULL, __VA_ARGS__)

#define INFO(...) \
	exe->log(NULL, NML_LOG_INFO, "firewall", NULL, __VA_ARGS__)

#define VERBOSE(...) \
do { \
	if (exe->log_level >= NML_LOG_VERBOSE) \
		exe->log(NULL, NML_LOG_VERBOSE, "firewall", NULL, __VA_ARGS__); \
} while (0)

#define DEBUG(...) \
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
    `netmill firewall`  interface NAME  RULE...\n\
Options:\n\
  `interface` NAME\n\
RULE:\n\
  `ip_proto` icmp|udp|tcp|NUMBER\n\
  `l4_src_port` N\n\
  `l4_dst_port` N\n\
");
	return R_DONE;
}

#include <ffsys/std.h>
#include <ffbase/args.h>
#include <ffbase/mem-print.h>
#include <firewall/data.h>
#include <firewall/fw.h>
#include <util/util.h>
#include <util/ethernet.h>
#include <util/ipaddr.h>
#include <util/udp.h>

#define RX_BURST_SIZE  128

struct firewall_conf {
	uint	if_index;
	const char *if_name;
	const char *obj_filename;
	struct firewall_rule rule;
	ffvec	rules; // struct firewall_rule[]
};

struct firewall {
	uint stop;

	lxdp lx;
	struct nml_fw_maps maps;
	lxdpsk lxsk;

	lxdpbuf* packets[RX_BURST_SIZE];

	uint ncpu;
	struct nml_fw_stats *stats;

	struct firewall_conf conf;
};

static int fw_attach(struct firewall *fw)
{
	struct lxdp_attach_conf conf = {};
	if (lxdp_attach(&fw->lx, fw->conf.obj_filename, fw->conf.if_index, &conf)) {
		ERR("lxdp_attach: %s", lxdp_error(&fw->lx));
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
		ERR("lxdpsk_create: %s", lxdp_error(&fw->lx));
		return -1;
	}
	if (lxdpsk_enable(&fw->lxsk, fw->maps.xsk)) {
		ERR("lxdpsk_enable: %s", lxdp_error(&fw->lx));
		return -1;
	}
	return 0;
}

static int fw_mask_add(struct nml_fw_maps *m, const struct firewall_rule *rule)
{
	struct nml_fw_rule v = {};
	v.ip_proto = (rule->ip_proto) ? 0xff : 0;
	*(ushort*)v.l4_src_port = (rule->l4_src_port) ? 0xffff : 0;
	*(ushort*)v.l4_dst_port = (rule->l4_dst_port) ? 0xffff : 0;

	struct nml_fw_rule *um;
	FFSLICE_WALK(&m->umasks, um) {
		if (*(uint64*)&v == *(uint64*)um)
			return 0; // this mask already exists
	}

	uint key = m->umasks.len;
	if (bpf_map__update_elem(m->masks, &key, sizeof(key), &v, sizeof(v), 0)) {
		ERR("bpf_map__update_elem");
		return -1;
	}

	*(uint64*)ffvec_pushT(&m->umasks, struct nml_fw_rule) = *(uint64*)&v;
	return 0;
}

int fw_rule_add(struct nml_fw_maps *m, const struct firewall_rule *rule)
{
	VERBOSE("Installing rule: ip:%xu  l4src:%u  l4dst:%u"
		, rule->ip_proto, rule->l4_src_port, rule->l4_dst_port);

	struct nml_fw_rule k = {};
	k.ip_proto = rule->ip_proto;
	*(ushort*)k.l4_src_port = ffint_be_cpu16(rule->l4_src_port);
	*(ushort*)k.l4_dst_port = ffint_be_cpu16(rule->l4_dst_port);

	u_char v = 0;
	if (bpf_map__update_elem(m->rules, &k, sizeof(k), &v, sizeof(v), 0)) {
		ERR("bpf_map__update_elem");
		return -1;
	}

	return fw_mask_add(m, rule);
}

int nml_fw_maps_init(struct lxdp *lx, struct nml_fw_maps *m)
{
	static const struct lxdp_map_name maps[] = {
		{ "nml_fw_mask_map",	FF_OFF(struct nml_fw_maps, masks) },
		{ "nml_fw_rule_map",	FF_OFF(struct nml_fw_maps, rules) },
		{ "nml_fw_stats_map",	FF_OFF(struct nml_fw_maps, stats) },
		{ "nml_fw_xsk_map",		FF_OFF(struct nml_fw_maps, xsk) },
		{}
	};
	if (lxdp_maps_link(lx, maps, m)) {
		ERR("lxdp_maps_link", lxdp_error(lx));
		return -1;
	}
	return 0;
}

static int fw_maps_init(struct firewall *fw)
{
	if (nml_fw_maps_init(&fw->lx, &fw->maps))
		return -1;

	struct firewall_rule *rule;
	FFSLICE_WALK(&fw->conf.rules, rule) {
		if (fw_rule_add(&fw->maps, rule))
			return -1;
	}

	return 0;
}

static void fw_stats_prepare(struct firewall *fw)
{
	fw->ncpu = libbpf_num_possible_cpus();
	uint cap = fw->ncpu * sizeof(struct nml_fw_stats);
	fw->stats = ffmem_alloc(cap);
}

static void fw_stats_close(struct firewall *fw)
{
	ffmem_free(fw->stats);
}

static int fw_stats_display(struct firewall *fw)
{
	int e;
	__u32 key = 0;
	uint cap = fw->ncpu * sizeof(struct nml_fw_stats);
	struct nml_fw_stats *s = fw->stats;
	if ((e = bpf_map__lookup_elem(fw->maps.stats, &key, sizeof(key), s, cap, 0))) {
		ERR("bpf_map__lookup_elem: %E", -e);
		return -1;
	}

	// Aggregate the data from all workers
	for (uint i = 1;  i < fw->ncpu;  i++) {
		s->invalid += s[i].invalid;
		s->matched += s[i].matched;
	}

	ffvec v = {};
	ffvec_addfmt(&v,
		"Stats:\n"
		" matched:\t%,U\n"
		" invalid:\t%,U\n"
		, s->matched
		, s->invalid);
	ffstdout_write(v.ptr, v.len);
	ffvec_free(&v);
	return 0;
}

static void fw_cleanup(struct firewall *fw)
{
	nml_fw_maps_close(&fw->maps);
	fw_stats_close(fw);
	fw_detach(fw);
	ffvec_free(&fw->conf.rules);
	ffmem_free(fw);
}

static int fw_setup(struct firewall *fw)
{
	if (fw_attach(fw)) goto err;
	if (fw_maps_init(fw)) goto err;
	if (fw_xsk_init(fw)) goto err;
	fw_stats_prepare(fw);
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
	buf[len++] = ' ';
	buf[len++] = ' ';
	if (ip->proto == FFIP_UDP)
		len += udp_hdr_str((struct udp_hdr*)((char*)ip + ffip4_hdr_len(ip)), buf + len, sizeof(buf) - len);

	buf[len++] = '\n';
	len += ffmem_print(buf + len, sizeof(buf) - len, lxdpbuf_data(p), p->len, 0, 0);
	VERBOSE("input: %*s", (size_t)len, buf);
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
				DEBUG("lxdpsk_write");
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
		SYSERR("ffkq_attach");
		return -1;
	}

	ffkq_time t;
	ffkq_time_set(&t, -1);
	ffkq_event events[1];
	while (!FFINT_READONCE(fw->stop)) {
		int r = ffkq_wait(kq, events, 1, t);
		if (r < 0) {
			if (errno != EINTR)
				SYSERR("ffkq_wait");
			break;
		}
		// DEBUG("ffkq_wait");
		if (r > 0)
			fw_process(fw);
	}

	fw_stats_display(fw);
	return 0;
}

static void fw_stop(struct firewall *fw)
{
	FFINT_WRITEONCE(fw->stop, 1);
}

static int fw_conf_check(struct firewall_conf *c)
{
	if (!c->if_index) {
		ERR("Please specify interface");
		return R_BADVAL;
	}

	if (!c->rule.ip_proto) {
		ERR("Please specify ip_proto");
		return R_BADVAL;
	}

	if ((c->rule.l4_src_port || c->rule.l4_dst_port)
		&& !(c->rule.ip_proto == FFIP_UDP || c->rule.ip_proto == FFIP_TCP)) {
		ERR("l4_src_port and l4_dst_port are for UDP or TCP only");
		return R_BADVAL;
	}

	*ffslice_lastT(&c->rules, struct firewall_rule) = c->rule;
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

static int fw_ip_proto(struct firewall_conf *c, ffstr name)
{
	uint n;
	if (ffstr_ieqz(&name, "icmp"))
		n = FFIP_ICMP;
	else if (ffstr_ieqz(&name, "tcp"))
		n = FFIP_TCP;
	else if (ffstr_ieqz(&name, "udp"))
		n = FFIP_UDP;
	else {
		if (!ffstr_to_uint32(&name, &n) || n == 0)
			return R_BADVAL;
	}

	if (c->rules.len) {
		*ffslice_lastT(&c->rules, struct firewall_rule) = c->rule;
		ffmem_zero_obj(&c->rule);
	}

	ffvec_pushT(&c->rules, struct firewall_rule);
	c->rule.ip_proto = n;
	return 0;
}

#define O(m)  (void*)(size_t)FF_OFF(struct firewall_conf, m)
static const struct ffarg firewall_args[] = {
	{ "help",		'1',	fw_help },
	{ "interface",	'S',	fw_interface },
	{ "ip_proto",	'+S',	fw_ip_proto },
	{ "l4_dst_port",'+u',	O(rule.l4_dst_port) },
	{ "l4_src_port",'+u',	O(rule.l4_src_port) },
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
			ERR("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			ERR("command line: %s\n", as.error);
		return NULL;
	}

	fw->conf.obj_filename = exe->path("ops/nmlfw-xdp-ebpf.o");
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
