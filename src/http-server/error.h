/** netmill: http-server: error document
2022, Simon Zolin */

#include <http-server/conn.h>

static int hs_err_open(nml_http_sv_conn *c)
{
	if (!c->resp_err)
		return NMLR_SKIP;
	return NMLR_OPEN;
}

static void hs_err_close(nml_http_sv_conn *c)
{
}

static int hs_err_process(nml_http_sv_conn *c)
{
	ffstr_setz(&c->resp.content_type, "text/plain");
	c->resp.content_length = c->resp.msg.len;
	c->resp_done = 1;
	ffstr_setstr(&c->output, &c->resp.msg);
	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_error = {
	hs_err_open, hs_err_close, hs_err_process,
	"error"
};
