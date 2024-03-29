/** netmill: http-server: data transfer filter
2022, Simon Zolin */

#include <http-server/client.h>

static int http_sv_transfer_open(nml_http_sv_conn *c)
{
	if (c->resp.content_length != ~0ULL) {
		c->transfer.cont_len = c->resp.content_length;
		return NMLF_OPEN;
	}

	c->resp_connection_keepalive = 0;
	return NMLF_SKIP;
}

static void http_sv_transfer_close(nml_http_sv_conn *c)
{
}

static int http_sv_transfer_process(nml_http_sv_conn *c)
{
	if (c->chain_going_back)
		return NMLF_BACK;

	ffsize n = ffmin64(c->input.len, c->transfer.cont_len);
	ffstr_set(&c->output, c->input.ptr, n);
	c->transfer.cont_len -= n;
	if (c->transfer.cont_len == 0)
		return NMLF_DONE;
	return NMLF_FWD;
}

const nml_http_sv_component nml_http_sv_transfer = {
	http_sv_transfer_open, http_sv_transfer_close, http_sv_transfer_process,
	"transfer"
};
