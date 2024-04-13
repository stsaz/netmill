/** netmill: UDP listener
2023, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/ipaddr.h>
#include <ffsys/socket.h>

struct nml_udp_listener {
	struct nml_udp_listener_conf conf;
	struct zzkevent sk_kev;
	ffsock sk;
	ffvec buf;
	ffsockaddr peer;
};

#define UL_SYSERR(l, ...) \
	l->conf.log(l->conf.log_obj, NML_LOG_SYSERR, "udp-lis", NULL, __VA_ARGS__)

#define UL_VERBOSE(l, ...) \
do { \
	if (l->conf.log_level >= NML_LOG_VERBOSE) \
		l->conf.log(l->conf.log_obj, NML_LOG_VERBOSE, "udp-lis", NULL, __VA_ARGS__); \
} while (0)

#define UL_DEBUG(l, ...) \
do { \
	if (l->conf.log_level >= NML_LOG_DEBUG) \
		l->conf.log(l->conf.log_obj, NML_LOG_DEBUG, "udp-lis", NULL, __VA_ARGS__); \
} while (0)

static nml_udp_listener* nml_udp_listener_create()
{
	nml_udp_listener *l = ffmem_new(struct nml_udp_listener);
	if (!l) return NULL;

	l->sk = FFSOCK_NULL;
	return l;
}

static void nml_udp_listener_destroy(nml_udp_listener *l)
{
	if (!l) return;

	ffsock_close(l->sk);
	ffvec_free(&l->buf);
	ffmem_free(l);
}

static void ul_log(void *opaque, ffuint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void udp_conf_init(struct nml_udp_listener_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = ul_log;
}

static int ul_sock_prepare(nml_udp_listener *l)
{
	const struct nml_address *a = &l->conf.addr;

	const void *ip4 = ffip6_tov4((void*)a->ip);
	uint sock_family = (ip4) ? AF_INET : AF_INET6;
	if (FFSOCK_NULL == (l->sk = ffsock_create_udp(sock_family, FFSOCK_NONBLOCK))) {
		UL_SYSERR(l, "ffsock_create_udp");
		return -1;
	}

	ffsockaddr addr = {};
	if (ip4) {
		ffsockaddr_set_ipv4(&addr, ip4, a->port);
	} else {
		ffsockaddr_set_ipv6(&addr, a->ip, a->port);

		// Allow clients to connect via IPv4
		if (!l->conf.v6_only
			&& ffip6_isany((void*)a->ip)
			&& ffsock_setopt(l->sk, IPPROTO_IPV6, IPV6_V6ONLY, 0)) {
			UL_SYSERR(l, "ffsock_setopt(IPV6_V6ONLY)");
			return -1;
		}
	}

#ifdef FF_UNIX
	// Allow several listening sockets to bind to the same address/port.
	// OS automatically distributes the load among the sockets.
	if (l->conf.reuse_port
		&& ffsock_setopt(l->sk, SOL_SOCKET, SO_REUSEPORT, 1)) {
		UL_SYSERR(l, "ffsock_setopt(SO_REUSEPORT)");
		return -1;
	}
#endif

	if (ffsock_bind(l->sk, &addr)) {
		UL_SYSERR(l, "socket bind");
		return -1;
	}

	UL_VERBOSE(l, "listening on %u", a->port);
	return 0;
}

static void ul_accept(nml_udp_listener *l);

static int nml_udp_listener_conf(nml_udp_listener *l, struct nml_udp_listener_conf *conf)
{
	if (!l) {
		udp_conf_init(conf);
		return 0;
	}

	l->conf = *conf;

	if (NULL == ffvec_alloc(&l->buf, 64*1024, 1))
		return -1;

	if (ul_sock_prepare(l))
		return -1;

	l->sk_kev.rhandler = (zzkevent_func)ul_accept;
	if (l->conf.core.kq_attach(l->conf.opaque, l->sk, &l->sk_kev, l))
		return -1;

	return 0;
}

static int ul_accept1(nml_udp_listener *l)
{
	int r = ffsock_recvfrom_async(l->sk, l->buf.ptr, l->buf.cap, &l->peer, &l->sk_kev.rtask);
	if (r < 0) {

#ifdef FF_WIN
		// handle "port unreachable" error from the previous sendto()
		if (fferr_last() == WSAECONNRESET
			|| fferr_last() == ERROR_PORT_UNREACHABLE) {
			UL_DEBUG(l, "ffsock_recvfrom: %E", fferr_last());
			return 0;
		}
#endif

		if (fferr_last() != FFSOCK_EINPROGRESS)
			UL_SYSERR(l, "ffsock_recvfrom");
		return -1;
	}

	ffstr data = FFSTR_INITN(l->buf.ptr, r);
	l->conf.on_recv_udp(l->conf.opaque, l->sk, &l->peer, data);

	ffvec_null(&l->buf);
	if (NULL == ffvec_alloc(&l->buf, 64*1024, 1))
		return -1;

	return 0;
}

static void ul_accept(nml_udp_listener *l)
{
	for (;;) {
		if (ul_accept1(l))
			break;
	}
}

static int nml_udp_listener_run(nml_udp_listener *l)
{
	ul_accept(l);
	return 0;
}

const struct nml_udp_listener_if nml_udp_listener_interface = {
	nml_udp_listener_create,
	nml_udp_listener_destroy,
	nml_udp_listener_conf,
	nml_udp_listener_run,
};
