/** netmill: http-client: outbound TCP connection
2023, Simon Zolin */

#include <http-client/client.h>

static int http_cl_connect_open(nml_http_client *c)
{
	if (c->connection_from_cache)
		return NMLF_SKIP;
	c->sk = FFSOCK_NULL;
	return NMLF_OPEN;
}

static void http_cl_connect_close(nml_http_client *c)
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
		cl_syswarnlog(c, "ffsock_create");
		return NMLF_ERR;
	}

	if (ffsock_setopt(c->sk, IPPROTO_TCP, TCP_NODELAY, 1))
		cl_syswarnlog(c, "ffsock_setopt(TCP_NODELAY)");

	if (c->conf->core.kq_attach(c->conf->boss, c->sk, c->kev, c)) {
		return NMLF_ERR;
	}

	return NMLF_FWD;
}

static void nml_connect_expired(nml_http_client *c)
{
	cl_warnlog(c, "connect timeout");
	c->timeout = 1;
	c->wake(c);
}

static void nml_connect_complete(nml_http_client *c)
{
	c->wake(c);
}

static int nml_connect(nml_http_client *c)
{
	int r = ffsock_connect_async(c->sk, &c->connect.saddr, cl_kev_w(c));
	cl_timer_stop(c, &c->connect.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_timer(c, &c->connect.timer, -(int)c->conf->connect_timeout_msec, nml_connect_expired, c);

			char buf[FFIP6_STRLEN];
			uint port;
			ffslice ip = ffsockaddr_ip_port(&c->connect.saddr, &port);
			ffip6 ip6;
			if (ip.len == 4)
				ffip6_v4mapped_set(&ip6, (void*)ip.ptr);
			else
				ffmem_copy(&ip6, ip.ptr, 16);
			ffsize n = ffip46_tostr(&ip6, buf, sizeof(buf));
			cl_verblog(c, "connecting to %S (%*s)...", &c->conf->host, n, buf);
			cl_kev_w_async(c, nml_connect_complete);
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "connect");
		return NMLF_ERR;
	}

	c->output = c->input;
	return NMLF_FWD;
}

static int http_cl_connect_process(nml_http_client *c)
{
	for (;;) {

		if (c->timeout) {
			return NMLF_ERR;
		}

		if (c->sk == FFSOCK_NULL) {
			if (c->connect.i_addr == c->resolve.addrs.len) {
				cl_errlog(c, "no next address to connect");
				return NMLF_ERR;
			}

			if (NMLF_ERR == nml_connect_prepare(c))
				goto next;
		}

		int r = nml_connect(c);
		if (r == NMLF_ERR)
		{}
		else if (r == NMLF_FWD)
			break;
		else
			return r;

next:
		ffsock_close(c->sk);  c->sk = FFSOCK_NULL;
	}

	cl_dbglog(c, "connect ok");
	return NMLF_DONE;
}

const nml_http_cl_component nml_http_cl_connect = {
	http_cl_connect_open, http_cl_connect_close, http_cl_connect_process,
	"connect"
};
