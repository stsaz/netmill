/** netmill: SOCKS Server: outbound TCP connection
2026, Simon Zolin */

#include <socks-server/conn.h>

static int sksv_connect_open(nml_socks_sv_conn *c)
{
	if (c->resp_err)
		return NMLR_SKIP;

	c->io.sk = FFSOCK_NULL;
	return NMLR_OPEN;
}

static void sksv_connect_close(nml_socks_sv_conn *c)
{
	sksv_timer_stop(c, &c->connect.timer);
	ffsock_close(c->io.sk);  c->io.sk = FFSOCK_NULL;
	c->conf->core.kev_free(c->conf->boss, c->io.kev);
}

static int sksv_connect_prepare(nml_socks_sv_conn *c, ffip6 ip)
{
	if (ffip6_v4mapped(&ip))
		ffsockaddr_set_ipv4(&c->connect.saddr, ffip6_tov4(&ip), c->connect.port);
	else
		ffsockaddr_set_ipv6(&c->connect.saddr, &ip, c->connect.port);

	if (FFSOCK_NULL == (c->io.sk = ffsock_create_tcp(c->connect.saddr.ip4.sin_family, FFSOCK_NONBLOCK))) {
		SKSV_SYSWARN(c, "ffsock_create");
		return NMLR_ERR;
	}

	if (ffsock_setopt(c->io.sk, IPPROTO_TCP, TCP_NODELAY, 1))
		SKSV_SYSWARN(c, "ffsock_setopt(TCP_NODELAY)");

	if (!(c->io.kev = c->conf->core.kev_new(c->conf->boss))
		|| c->conf->core.kq_attach(c->conf->boss, c->io.sk, c->io.kev, c))
		return NMLR_ERR;

	return NMLR_FWD;
}

static void sksv_connect_expired(nml_socks_sv_conn *c)
{
	SKSV_WARN(c, "connect timeout");
	c->timeout = 1;
	c->conf->cl_wake(c);
}

static void sksv_connect_complete(nml_socks_sv_conn *c)
{
	c->conf->cl_wake(c);
}

static int sksv_connect(nml_socks_sv_conn *c)
{
	int r = ffsock_connect_async(c->io.sk, &c->connect.saddr, SKSV_UP_KEV_W(c));
	sksv_timer_stop(c, &c->connect.timer);
	if (r < 0) {
		char buf[FFIP6_STRLEN];
		uint port = 0;
		ffslice ip = ffsockaddr_ip_port(&c->connect.saddr, &port);
		ffip6 ip6;
		if (ip.len == 4)
			ffip6_v4mapped_set(&ip6, (void*)ip.ptr);
		else
			ffmem_copy(&ip6, ip.ptr, 16);
		uint n = ffip46_tostr(&ip6, buf, sizeof(buf));
		ffstr host = {};
		if (c->resolve.hostname)
			ffstr_setz(&host, c->resolve.hostname);

		if (fferr_last() == FFSOCK_EINPROGRESS) {
			sksv_timer(c, &c->connect.timer, -(int)c->conf->connect_timeout_sec, sksv_connect_expired, c);
			SKSV_VERBOSE(c, "connecting to %S (%*s:%u)..."
				, &host, n, buf, port);
			SKSV_UP_ASYNC_W(c, sksv_connect_complete);
			return NMLR_ASYNC;
		}
		SKSV_SYSWARN(c, "connect to %S (%*s:%u)"
				, &host, n, buf, port);
		return NMLR_ERR;
	}

	c->output = c->input;
	return NMLR_FWD;
}

static int sksv_connect_process(nml_socks_sv_conn *c)
{
	for (;;) {

		if (c->timeout) {
			return NMLR_ERR;
		}

		if (c->io.sk == FFSOCK_NULL) {
			if (c->connect.i_addr == c->resolve.addrs.len) {
				SKSV_DEBUG(c, "no next address to connect");
				sksv_response_err(c, 1);
				return NMLR_DONE;
			}

			ffip6 ip = *ffslice_itemT(&c->resolve.addrs, c->connect.i_addr, ffip6);
			c->connect.i_addr++;
			if (NMLR_ERR == sksv_connect_prepare(c, ip))
				goto next;
		}

		int r = sksv_connect(c);
		if (r == NMLR_ERR)
		{}
		else if (r == NMLR_FWD)
			break;
		else
			return r;

next:
		ffsock_close(c->io.sk);  c->io.sk = FFSOCK_NULL;
	}

	SKSV_DEBUG(c, "connect ok");
	return NMLR_DONE;
}

const nml_socks_sv_component nml_sksv_connect = {
	sksv_connect_open, sksv_connect_close, sksv_connect_process,
	"connect"
};
