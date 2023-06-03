/** netmill: http-server: keep-alive
2023, Simon Zolin */

#include <http-server/client.h>

static int nml_ka_open(nml_http_sv_conn *c)
{
	return NMLF_OPEN;
}

static void nml_ka_close(nml_http_sv_conn *c)
{
	ffvec rb = c->recv.req; // preserve pipelined data
	ffmem_zero(&c->start_time_msec, sizeof(*c) - FF_OFF(nml_http_sv_conn, start_time_msec));
	ffkcall_cancel(&c->kev->kcall);
	c->recv.req = rb;
}

static int nml_ka_process(nml_http_sv_conn *c)
{
	if (!c->resp_connection_keepalive)
		return NMLF_FIN;

	c->keep_alive_n++;
	if (c->keep_alive_n == c->conf->max_keep_alive_reqs)
		return NMLF_FIN;

	return NMLF_RESET;
}

const struct nml_filter nml_filter_keepalive = {
	(void*)nml_ka_open, (void*)nml_ka_close, (void*)nml_ka_process,
	"keep-alive"
};
