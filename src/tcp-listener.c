/** netmill: tcp listener
2022, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/ipaddr.h>
#include <FFOS/socket.h>

struct nml_tcp_listener {
	struct nml_tcp_listener_conf conf;
	struct zzkevent lsock_kev;
	ffsock lsock;
	nml_timer tmr_fdlimit;
	uint sock_family;
};

#define ls_syserrlog(l, ...) \
	l->conf.log(l->conf.log_obj, NML_LOG_SYSERR, "tcp-lis", NULL, __VA_ARGS__)

#define ls_warnlog(l, ...) \
	l->conf.log(l->conf.log_obj, NML_LOG_WARN, "tcp-lis", NULL, __VA_ARGS__)

#define ls_verblog(l, ...) \
do { \
	if (l->conf.log_level >= NML_LOG_VERBOSE) \
		l->conf.log(l->conf.log_obj, NML_LOG_VERBOSE, "tcp-lis", NULL, __VA_ARGS__); \
} while (0)

nml_tcp_listener* nml_tcp_listener_new()
{
	nml_tcp_listener *l = ffmem_new(struct nml_tcp_listener);
	l->lsock = FFSOCK_NULL;
	return l;
}

void nml_tcp_listener_free(nml_tcp_listener *l)
{
	if (l == NULL) return;

	ffsock_close(l->lsock);
	ffmem_free(l);
}

static void ls_log(void *opaque, ffuint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void ls_conf_init(struct nml_tcp_listener_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = ls_log;

	conf->fdlimit_timeout_sec = 10;
	conf->backlog = SOMAXCONN;
}

static int lsock_prepare(nml_tcp_listener *l)
{
	const struct nml_address *a = &l->conf.addr;

	const void *ip4 = ffip6_tov4((void*)a->ip);
	l->sock_family = (ip4 != NULL) ? AF_INET : AF_INET6;
	if (FFSOCK_NULL == (l->lsock = ffsock_create_tcp(l->sock_family, FFSOCK_NONBLOCK))) {
		ls_syserrlog(l, "ffsock_create_tcp");
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
			&& 0 != ffsock_setopt(l->lsock, IPPROTO_IPV6, IPV6_V6ONLY, 0)) {
			ls_syserrlog(l, "ffsock_setopt(IPV6_V6ONLY)");
			return -1;
		}
	}

#ifdef FF_UNIX
	// Allow several listening sockets to bind to the same address/port.
	// OS automatically distributes the load among the sockets.
	if (l->conf.reuse_port
		&& 0 != ffsock_setopt(l->lsock, SOL_SOCKET, SO_REUSEPORT, 1)) {
		ls_syserrlog(l, "ffsock_setopt(SO_REUSEPORT)");
		return -1;
	}
#endif

	if (0 != ffsock_bind(l->lsock, &addr)) {
		ls_syserrlog(l, "socket bind");
		return -1;
	}

	if (0 != ffsock_listen(l->lsock, l->conf.backlog)) {
		ls_syserrlog(l, "socket listen");
		return -1;
	}

	ls_verblog(l, "listening on %u", a->port);
	return 0;
}

static void ls_accept(nml_tcp_listener *l);

int nml_tcp_listener_conf(nml_tcp_listener *l, struct nml_tcp_listener_conf *conf)
{
	if (l == NULL) {
		ls_conf_init(conf);
		return 0;
	}

	l->conf = *conf;

	if (0 != lsock_prepare(l))
		return -1;

	l->lsock_kev.rhandler = (zzkevent_func)ls_accept;
	if (0 != l->conf.core.kq_attach(l->conf.boss, l->lsock, &l->lsock_kev, l)) {
		return -1;
	}

	return 0;
}

static int ls_accept1(nml_tcp_listener *l)
{
	// if (l->conf.kq->kevs_allocated == l->conf.kq->conf.max_objects) {
	// 	ls_warnlog(l, "reached max worker connections limit");
	// 	l->conf.core.timer(l->conf.boss, &l->tmr_fdlimit, -(int)l->conf.fdlimit_timeout_sec*1000, (fftimerqueue_func)ls_accept, l);
	// 	return -1;
	// }

	ffsock csock;
	ffsockaddr peer;
	if (FFSOCK_NULL == (csock = ffsock_accept_async(l->lsock, &peer, FFSOCK_NONBLOCK, l->sock_family, NULL, &l->lsock_kev.rtask_accept))) {
		if (fferr_last() == FFSOCK_EINPROGRESS)
			return -1;

		if (fferr_fdlimit(fferr_last())) {
			ls_syserrlog(l, "ffsock_accept");
			l->conf.core.timer(l->conf.boss, &l->tmr_fdlimit, -(int)l->conf.fdlimit_timeout_sec*1000, (fftimerqueue_func)ls_accept, l);
			return -1;
		}

		ls_syserrlog(l, "ffsock_accept");
		return -1;
	}

	l->conf.on_accept(l->conf.boss, csock, &peer);
	return 0;
}

/** Accept a bunch of client connections */
static void ls_accept(nml_tcp_listener *l)
{
	for (;;) {
		if (0 != ls_accept1(l))
			break;
	}
}

int nml_tcp_listener_run(nml_tcp_listener *l)
{
	ls_accept(l);
	return 0;
}
