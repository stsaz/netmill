/** netmill: UDP listener
2023, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/ipaddr.h>
#include <FFOS/socket.h>

struct nml_udp_listener {
	struct nml_udp_listener_conf conf;
	struct zzkevent sk_kev;
	ffsock sk;
	ffvec buf;
	ffsockaddr peer;
};

#define udp_syserrlog(l, ...) \
	l->conf.log(l->conf.log_obj, NML_LOG_SYSERR, "udp-lis", NULL, __VA_ARGS__)

#define udp_verblog(l, ...) \
do { \
	if (l->conf.log_level >= NML_LOG_VERBOSE) \
		l->conf.log(l->conf.log_obj, NML_LOG_VERBOSE, "udp-lis", NULL, __VA_ARGS__); \
} while (0)

#define udp_dbglog(l, ...) \
do { \
	if (l->conf.log_level >= NML_LOG_DEBUG) \
		l->conf.log(l->conf.log_obj, NML_LOG_DEBUG, "udp-lis", NULL, __VA_ARGS__); \
} while (0)

nml_udp_listener* nml_udp_listener_new()
{
	nml_udp_listener *l = ffmem_new(struct nml_udp_listener);
	l->sk = FFSOCK_NULL;
	return l;
}

void nml_udp_listener_free(nml_udp_listener *l)
{
	if (l == NULL) return;

	ffsock_close(l->sk);
	ffvec_free(&l->buf);
	ffmem_free(l);
}

static void udp_log(void *opaque, ffuint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void udp_conf_init(struct nml_udp_listener_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = udp_log;
}

static int lsock_prepare(nml_udp_listener *l)
{
	const struct nml_address *a = &l->conf.addr;

	const void *ip4 = ffip6_tov4((void*)a->ip);
	uint sock_family = (ip4 != NULL) ? AF_INET : AF_INET6;
	if (FFSOCK_NULL == (l->sk = ffsock_create_udp(sock_family, FFSOCK_NONBLOCK))) {
		udp_syserrlog(l, "ffsock_create_udp");
		return -1;
	}

	ffsockaddr addr = {};
	if (ip4 != NULL) {
		ffsockaddr_set_ipv4(&addr, ip4, a->port);
	} else {
		ffsockaddr_set_ipv6(&addr, a->ip, a->port);

		// Allow clients to connect via IPv4
		if (!l->conf.v6_only
			&& ffip6_isany((void*)a->ip)
			&& 0 != ffsock_setopt(l->sk, IPPROTO_IPV6, IPV6_V6ONLY, 0)) {
			udp_syserrlog(l, "ffsock_setopt(IPV6_V6ONLY)");
			return -1;
		}
	}

#ifdef FF_UNIX
	// Allow several listening sockets to bind to the same address/port.
	// OS automatically distributes the load among the sockets.
	if (l->conf.reuse_port
		&& 0 != ffsock_setopt(l->sk, SOL_SOCKET, SO_REUSEPORT, 1)) {
		udp_syserrlog(l, "ffsock_setopt(SO_REUSEPORT)");
		return -1;
	}
#endif

	if (0 != ffsock_bind(l->sk, &addr)) {
		udp_syserrlog(l, "socket bind");
		return -1;
	}

	udp_verblog(l, "listening on %u", a->port);
	return 0;
}

static void udp_accept(nml_udp_listener *l);

int nml_udp_listener_conf(nml_udp_listener *l, struct nml_udp_listener_conf *conf)
{
	if (l == NULL) {
		udp_conf_init(conf);
		return 0;
	}

	l->conf = *conf;

	if (!ffvec_alloc(&l->buf, 64*1024, 1))
		return -1;

	if (lsock_prepare(l))
		return -1;

	l->sk_kev.rhandler = (zzkevent_func)udp_accept;
	if (0 != l->conf.core.kq_attach(l->conf.boss, l->sk, &l->sk_kev, l))
		return -1;

	return 0;
}

static int udp_accept1(nml_udp_listener *l)
{
	int r = ffsock_recvfrom_async(l->sk, l->buf.ptr, l->buf.cap, &l->peer, &l->sk_kev.rtask);
	if (r < 0) {

#ifdef FF_WIN
		// handle "port unreachable" error from the previous sendto()
		if (fferr_last() == WSAECONNRESET
			|| fferr_last() == ERROR_PORT_UNREACHABLE) {
			udp_dbglog(l, "ffsock_recvfrom: %E", fferr_last());
			return 0;
		}
#endif

		if (fferr_last() != FFSOCK_EINPROGRESS)
			udp_syserrlog(l, "ffsock_recvfrom");
		return -1;
	}

	ffstr data = FFSTR_INITN(l->buf.ptr, r);
	l->conf.on_recv_udp(l->conf.boss, l->sk, &l->peer, data);

	ffvec_null(&l->buf);
	if (!ffvec_alloc(&l->buf, 64*1024, 1))
		return -1;

	return 0;
}

static void udp_accept(nml_udp_listener *l)
{
	for (;;) {
		if (0 != udp_accept1(l))
			break;
	}
}

int nml_udp_listener_run(nml_udp_listener *l)
{
	udp_accept(l);
	return 0;
}
