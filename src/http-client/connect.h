/** netmill: http-client: outbound TCP connection
2023, Simon Zolin */

#include <http-client/client.h>

static int hc_connect_open(nml_http_client *c)
{
	if (c->connection_from_cache)
		return NMLR_SKIP;
	c->sk = FFSOCK_NULL;
	return NMLR_OPEN;
}

static void hc_connect_close(nml_http_client *c)
{
	ffsock_close(c->sk);  c->sk = FFSOCK_NULL;
}

static int nml_connect_prepare(nml_http_client *c)
{
	ffip6 ip = *ffslice_itemT(&c->resolve.addrs, c->connect.i_addr, ffip6);
	c->connect.i_addr++;
	if (ffip6_v4mapped(&ip))
		ffsockaddr_set_ipv4(&c->connect.saddr, ffip6_tov4(&ip), c->resolve.port);
	else
		ffsockaddr_set_ipv6(&c->connect.saddr, &ip, c->resolve.port);

	if (FFSOCK_NULL == (c->sk = ffsock_create_tcp(c->connect.saddr.ip4.sin_family, FFSOCK_NONBLOCK))) {
		HC_SYSWARN(c, "ffsock_create");
		return NMLR_ERR;
	}

	if (ffsock_setopt(c->sk, IPPROTO_TCP, TCP_NODELAY, 1))
		HC_SYSWARN(c, "ffsock_setopt(TCP_NODELAY)");

	if (c->conf->core.kq_attach(c->conf->boss, c->sk, c->kev, c)) {
		return NMLR_ERR;
	}

	return NMLR_FWD;
}

static void hc_connect_expired(nml_http_client *c)
{
	HC_WARN(c, "connect timeout");
	c->timeout = 1;
	c->wake(c);
}

static void hc_connect_complete(nml_http_client *c)
{
	c->wake(c);
}

static int hc_connect(nml_http_client *c)
{
	int r = ffsock_connect_async(c->sk, &c->connect.saddr, HC_KEV_W(c));
	hc_timer_stop(c, &c->connect.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hc_timer(c, &c->connect.timer, -(int)c->conf->connect_timeout_msec, hc_connect_expired, c);

			char buf[FFIP6_STRLEN];
			uint port;
			ffslice ip = ffsockaddr_ip_port(&c->connect.saddr, &port);
			ffip6 ip6;
			if (ip.len == 4)
				ffip6_v4mapped_set(&ip6, (void*)ip.ptr);
			else
				ffmem_copy(&ip6, ip.ptr, 16);
			size_t n = ffip46_tostr(&ip6, buf, sizeof(buf));
			HC_VERBOSE(c, "connecting to %S (%*s:%u)..."
				, (c->conf->proxy_host.len) ? &c->conf->proxy_host : &c->conf->host, n, buf, port);
			HC_ASYNC_W(c, hc_connect_complete);
			return NMLR_ASYNC;
		}
		HC_SYSWARN(c, "connect");
		return NMLR_ERR;
	}

	c->output = c->input;
	return NMLR_FWD;
}

static int hc_connect_process(nml_http_client *c)
{
	for (;;) {

		if (c->timeout) {
			return NMLR_ERR;
		}

		if (c->sk == FFSOCK_NULL) {
			if (c->connect.i_addr == c->resolve.addrs.len) {
				HC_ERR(c, "no next address to connect");
				return NMLR_ERR;
			}

			if (NMLR_ERR == nml_connect_prepare(c))
				goto next;
		}

		int r = hc_connect(c);
		if (r == NMLR_ERR)
		{}
		else if (r == NMLR_FWD)
			break;
		else
			return r;

next:
		ffsock_close(c->sk);  c->sk = FFSOCK_NULL;
	}

	HC_DEBUG(c, "connect ok");
	return NMLR_DONE;
}

const nml_http_cl_component nml_http_cl_connect = {
	hc_connect_open, hc_connect_close, hc_connect_process,
	"connect"
};
