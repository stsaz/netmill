/** netmill: XDP ping
2024, Simon Zolin */

#include <netmill.h>

extern const nml_exe *exe;

#define SYSERR(...) \
	exe->log(NULL, NML_LOG_SYSERR, "xping", NULL, __VA_ARGS__)

#define ERR(...) \
	exe->log(NULL, NML_LOG_ERR, "xping", NULL, __VA_ARGS__)

#define INFO(...) \
	exe->log(NULL, NML_LOG_INFO, "xping", NULL, __VA_ARGS__)

#define VERBOSE(...) \
do { \
	if (exe->log_level >= NML_LOG_VERBOSE) \
		exe->log(NULL, NML_LOG_VERBOSE, "xping", NULL, __VA_ARGS__); \
} while (0)

#define DEBUG(...) \
do { \
	if (exe->log_level >= NML_LOG_DEBUG) \
		exe->log(NULL, NML_LOG_DEBUG, "xping", NULL, __VA_ARGS__); \
} while (0)

#define R_DONE  100
#define R_BADVAL  101
#define R_ERR  102

static int xping_help()
{
	exe->print(
"XDP ping\n\
    `netmill ping` OPTIONS\n\
Options:\n\
  `interface` NAME\n\
  `hwsrc` MAC\n\
  `hwdst` MAC\n\
  `src` IP\n\
  `dst` IP\n\
  `period` MSEC (=1000)\n\
  `burst` N (=1)\n\
\n\
Example:\n\
    netmill ping inter eth1  hwsrc 11:11:11:11:11:11  hwdst 22:22:22:22:22:22  src 10.1.1.1  dst 10.1.1.2\n\
");
	return R_DONE;
}

#include <ffbase/args.h>
#include <ffsys/std.h>
#include <ffsys/perf.h>
#include <firewall/data.h>
#include <firewall/fw.h>
#include <ffsys/thread.h>
#include <ffbase/mem-print.h>
#include <util/util.h>
#include <util/ethernet.h>
#include <util/ipaddr.h>
#include <util/icmp.h>

struct xping_conf {
	uint	if_index;
	const char *if_name;

	u_char	hw_src[6], hw_dst[6];
	u_char	ip_src[4], ip_dst[4];

	uint	burst_size;
	uint	payload_len;
	uint	period_msec;
	ffstr	hwsrc, hwdst;
	ffstr	src, dst;
	const char *obj_filename;
};

struct xping {
	uint stop;

	lxdp lx;
	struct nml_fw_maps maps;
	lxdpsk lxsk;
	lxdpbuf **buffers;

	uint	seq;
	ffstr	payload;
	fftime	tstart, tstop;

	struct xping_conf conf;
};

static int xping_attach(struct xping *x)
{
	struct lxdp_attach_conf conf = {};
	if (lxdp_attach(&x->lx, x->conf.obj_filename, x->conf.if_index, &conf)) {
		ERR("lxdp_attach: %s", lxdp_error(&x->lx));
		return -1;
	}
	return 0;
}

static int xping_detach(struct xping *x)
{
	lxdp_close(&x->lx);
	return 0;
}

static int xping_xsk_init(struct xping *x)
{
	struct lxdpsk_conf conf = {};
	if (lxdpsk_create(&x->lx, &x->lxsk, x->conf.if_name, 0, &conf)) {
		ERR("lxdpsk_create: %s", lxdp_error(&x->lx));
		return -1;
	}
	if (lxdpsk_enable(&x->lxsk, x->maps.xsk)) {
		ERR("lxdpsk_enable: %s", lxdp_error(&x->lx));
		return -1;
	}
	return 0;
}

static int xping_maps_init(struct xping *x)
{
	if (nml_fw_maps_init(&x->lx, &x->maps))
		return -1;

	struct firewall_rule rule = {
		.ip_proto = FFIP_ICMP,
	};
	if (fw_rule_add(&x->maps, &rule))
		return -1;

	return 0;
}

static void xping_cleanup(struct xping *x)
{
	nml_fw_maps_close(&x->maps);
	xping_detach(x);
}

static int xping_setup(struct xping *x)
{
	x->buffers = ffmem_alloc(sizeof(void*) * x->conf.burst_size);
	if (xping_attach(x)) goto err;
	if (xping_maps_init(x)) goto err;
	if (xping_xsk_init(x)) goto err;

	ffstr_alloc(&x->payload, x->conf.payload_len);
	x->payload.len = x->conf.payload_len;
	char *d = x->payload.ptr;
	for (uint i = 0;  i < x->payload.len;  i++) {
		*d++ = i + 0x20;
	}

	return 0;

err:
	return -1;
}

static void xping_request_prepare(struct xping *x, lxdpbuf *p)
{
	void *data = p->data;

	struct eth_hdr *eth = data;
	struct ffip4_hdr *ip = (void*)(eth + 1);
	struct icmp_hdr *icmp = (void*)(ip + 1);
	data = (void*)(icmp + 1);

	data = ffmem_copy(data, x->payload.ptr, x->payload.len);

	eth_hdr_fill(eth, x->conf.hw_src, x->conf.hw_dst, ETH_IP4);
	ffip4_hdr_fill(ip, sizeof(*icmp) + x->payload.len, 1, 64, FFIP_ICMP, x->conf.ip_src, x->conf.ip_dst);
	icmp_hdr_echo_request(icmp, 1, ++x->seq, x->payload.len);

	p->len = (char*)data - (char*)p->data;

	if (0 && exe->log_level >= NML_LOG_DEBUG) {
		char buf[4000];
		size_t n = ffmem_print(buf, sizeof(buf), p->data, p->len, 0, 0);
		DEBUG("output: \n%*s", n, buf);
	}
}

static int xping_response_handle(struct xping *x, lxdpbuf *p)
{
	const void *data = lxdpbuf_data(p);
	const void *end = p->data + p->len;

	const struct ffip4_hdr *ip = lxdpbuf_data_off(p, p->off_ip);
	const struct icmp_hdr *icmp = data;

	if ((void*)(icmp + 1) > end
		|| ip->proto != FFIP_ICMP)
		return -1;

	DEBUG("icmp type:%u  id:%u  seq:%u"
		, icmp->type, ffint_be_cpu16_ptr(icmp->echo.id), ffint_be_cpu16_ptr(icmp->echo.seq));

	if (icmp->type != ICMP_ECHO_REPLY)
		return -1;

	char src[FFIP4_STRLEN + 1];
	uint n = ffip4_tostr((ffip4*)ip->src, src, sizeof(src));
	src[n] = '\0';

	fftime_sub(&x->tstop, &x->tstart);
	INFO("%u bytes from %s: icmp_seq=%u ttl=%u time=%ums"
		, ffip4_hdr_datalen(ip) - sizeof(*icmp)
		, src
		, ffint_be_cpu16_ptr(icmp->echo.seq)
		, ip->ttl
		, fftime_msec(&x->tstop)
		);
	return -1;
}

static int xping_request_handle(lxdpbuf *p)
{
	void *data = lxdpbuf_data(p);
	const void *end = p->data + p->len;

	struct eth_hdr *eth = (void*)p->data;
	struct ffip4_hdr *ip = lxdpbuf_data_off(p, p->off_ip);

	struct icmp_hdr *icmp = data;
	if ((void*)(icmp + 1) > end
		|| ip->proto != FFIP_ICMP)
		return -1;

	INFO("icmp type:%u  id:%u  seq:%u"
		, icmp->type, ffint_be_cpu16_ptr(icmp->echo.id), ffint_be_cpu16_ptr(icmp->echo.seq));

	if (icmp->type != ICMP_ECHO_REQUEST)
		return -1;

	icmp->type = ICMP_ECHO_REPLY;
	ip_sum_replace((ushort*)icmp->crc, ffint_be_cpu16(ICMP_ECHO_REQUEST << 8), ffint_be_cpu16(ICMP_ECHO_REPLY << 8));

	ffip4_swap(ip->src, ip->dst);

	eth_swap(eth->src, eth->dst);
	return 0;
}

static int xping_pkt(struct xping *x, lxdpbuf *p)
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
	DEBUG("input: %*s", (size_t)len, buf);

	if (0) {
		lxdpbuf_shift(p, ffip4_hdr_len(ip));
		return xping_request_handle(p);
	}

	if (1) {
		lxdpbuf_shift(p, ffip4_hdr_len(ip));
		return xping_response_handle(x, p);
	}

	return 0;
}

static void xping_process(struct xping *x)
{
	x->tstop = fftime_monotonic();
	for (;;) {
		uint n = lxdpsk_read(&x->lxsk, x->buffers, x->conf.burst_size);
		if (!n)
			break;

		for (uint i = 0;  i < n;  i++) {
			lxdpbuf *p = x->buffers[i];
			if (!xping_pkt(x, p)) {
			} else {
				lxdpsk_buf_release(&x->lxsk, p);
			}
		}
	}
}

static void xping_requests_send(struct xping *x)
{
	x->tstart = fftime_monotonic();
	uint n = lxdpsk_buf_alloc(&x->lxsk, x->buffers, x->conf.burst_size);
	for (uint i = 0;  i < n;  i++) {
		lxdpbuf *buf = x->buffers[i];
		xping_request_prepare(x, buf);
	}
	lxdpsk_write(&x->lxsk, x->buffers, n);
	lxdpsk_flush(&x->lxsk);
	DEBUG("output: %u", n);
}

static int xping_run(struct xping *x)
{
	ffkq kq = ffkq_create();
	if (ffkq_attach(kq, lxdpsk_fd(&x->lxsk), NULL, FFKQ_READ)) {
		SYSERR("ffkq_attach");
		return -1;
	}

	ffkq_time t;
	ffkq_time_set(&t, -1);
	ffkq_event events[1];
	while (!FFINT_READONCE(x->stop)) {

		xping_requests_send(x);

		int r = ffkq_wait(kq, events, 1, t);
		if (r < 0) {
			if (fferr_last() == EINTR)
				continue;
			SYSERR("ffkq_wait");
			break;
		}
		// DEBUG("ffkq_wait");
		if (r > 0)
			xping_process(x);

		if (x->conf.period_msec != 0)
			ffthread_sleep(x->conf.period_msec);
	}
	return 0;
}

static void xping_stop(struct xping *x)
{
	FFINT_WRITEONCE(x->stop, 1);
}

static int xping_conf_check(struct xping_conf *c)
{
	if (!c->if_index) {
		ERR("Please specify interface");
		return R_ERR;
	}

	if (!c->hwsrc.len || !c->hwdst.len
		|| !c->src.len || !c->dst.len) {
		ERR("Please specify hwsrc, hwdst, src and dst");
		return R_ERR;
	}

	if (eth_parse(c->hw_src, c->hwsrc.ptr, c->hwsrc.len)
		|| eth_parse(c->hw_dst, c->hwdst.ptr, c->hwdst.len)
		|| ffip4_parse((ffip4*)c->ip_src, c->src.ptr, c->src.len)
		|| ffip4_parse((ffip4*)c->ip_dst, c->dst.ptr, c->dst.len)) {
		ERR("Incorrect hwsrc, hwdst, src or dst");
		return R_ERR;
	}

	if (c->burst_size == 0 || c->burst_size > 256) {
		ERR("Too large burst size");
		return R_ERR;
	}

	return 0;
}

static int xping_interface(struct xping_conf *c, ffstr name)
{
	// if (!ffstr_to_uint32(&name, &c->if_index))
	c->if_index = ffnetconf_if_index(name);
	if (c->if_index == 0)
		return R_BADVAL;
	c->if_name = ffsz_dupstr(&name);
	return 0;
}

#define O(m)  (void*)(size_t)FF_OFF(struct xping_conf, m)
static const struct ffarg ping_args[] = {
	{ "burst",		'u',	O(burst_size) },
	{ "dst",		'S',	O(dst) },
	{ "help",		'1',	xping_help },
	{ "hwdst",		'S',	O(hwdst) },
	{ "hwsrc",		'S',	O(hwsrc) },
	{ "interface",	'S',	xping_interface },
	{ "period",		'u',	O(period_msec) },
	{ "src",		'S',	O(src) },
	{ "",			'1',	xping_conf_check },
	{}
};
#undef O

static nml_op* xping_create(char **argv)
{
	struct xping *x = ffmem_new(struct xping);
	x->conf.burst_size = 1;
	x->conf.payload_len = 64;
	x->conf.period_msec = 1000;

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, ping_args, &x->conf, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
		{}
		else if (r == R_BADVAL)
			ERR("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			ERR("command line: %s\n", as.error);
		return NULL;
	}

	x->conf.obj_filename = exe->path("ops/nmlfw-xdp-ebpf.o");
	return x;
}

static void xping_close(nml_op *op)
{
	xping_cleanup(op);
}

static void _xping_run(nml_op *op)
{
	if (xping_setup(op)) return;
	xping_run(op);
}

static void xping_signal(nml_op *op, uint signal)
{
	xping_stop(op);
}

const struct nml_operation_if nml_op_ping = {
	xping_create,
	xping_close,
	_xping_run,
	xping_signal,
};
