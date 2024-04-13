/** netmill: http-server: keep-alive
2023, Simon Zolin */

#include <http-server/conn.h>

static int hs_keepalive_open(nml_http_sv_conn *c)
{
	return NMLR_OPEN;
}

static void hs_keepalive_close(nml_http_sv_conn *c)
{
	ffvec rb = c->recv.req; // preserve pipelined data
	ffmem_zero(&c->start_time_msec, sizeof(*c) - FF_OFF(nml_http_sv_conn, start_time_msec));
	ffkcall_cancel(&c->kev->kcall);
	c->recv.req = rb;
}

static int hs_keepalive_process(nml_http_sv_conn *c)
{
	if (!c->resp_connection_keepalive)
		return NMLR_FIN;

	c->keep_alive_n++;
	if (c->keep_alive_n == c->conf->max_keep_alive_reqs)
		return NMLR_FIN;

	return NMLR_RESET;
}

const nml_http_sv_component nml_http_sv_keepalive = {
	hs_keepalive_open, hs_keepalive_close, hs_keepalive_process,
	"keep-alive"
};
