/** netmill: http-server: error document
2022, Simon Zolin */

#include <http-server/client.h>

static int http_sv_err_open(nml_http_sv_conn *c)
{
	if (!c->resp_err)
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void http_sv_err_close(nml_http_sv_conn *c)
{
}

static int http_sv_err_process(nml_http_sv_conn *c)
{
	ffstr_setz(&c->resp.content_type, "text/plain");
	c->resp.content_length = c->resp.msg.len;
	c->resp_done = 1;
	ffstr_setstr(&c->output, &c->resp.msg);
	return NMLF_DONE;
}

const nml_http_sv_component nml_http_sv_error = {
	http_sv_err_open, http_sv_err_close, http_sv_err_process,
	"error"
};
