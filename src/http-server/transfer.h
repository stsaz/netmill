/** netmill: http-server: data transfer filter
2022, Simon Zolin */

#include <http-server/conn.h>

static int hs_transfer_open(nml_http_sv_conn *c)
{
	if (c->resp.content_length != ~0ULL) {
		c->transfer.cont_len = c->resp.content_length;

	} else if (!c->req_no_chunked) {
		c->resp_transfer_encoding_chunked = 1;

	} else {
		c->resp_connection_keepalive = 0;
		return NMLR_SKIP;
	}

	return NMLR_OPEN;
}

static void hs_transfer_close(nml_http_sv_conn *c)
{
}

static int hs_transfer_process(nml_http_sv_conn *c)
{
	if (c->resp_transfer_encoding_chunked) {

		if (c->resp_done) {
			c->resp_done = 0;
			c->transfer_finish = 1;
		}

		if (c->chain_going_back && !c->transfer_finish)
			return NMLR_BACK;

		ffstr hdr, trl;
		httpchunked_write(c->transfer.buf, c->input.len, &hdr, &trl);
		ffiovec_set(&c->send.iov[0], hdr.ptr, hdr.len);
		ffiovec_set(&c->send.iov[1], c->input.ptr, c->input.len);
		ffiovec_set(&c->send.iov[2], trl.ptr, trl.len);
		c->send.iov_n = 3;
		if (c->transfer_finish && !c->input.len) {
			c->resp_done = 1;
			return NMLR_DONE;
		}
		return NMLR_FWD;
	}

	if (c->chain_going_back)
		return NMLR_BACK;

	size_t n = ffmin64(c->input.len, c->transfer.cont_len);
	ffstr_set(&c->output, c->input.ptr, n);
	c->transfer.cont_len -= n;
	if (c->transfer.cont_len == 0)
		return NMLR_DONE;
	return NMLR_FWD;
}

const nml_http_sv_component nml_http_sv_transfer = {
	hs_transfer_open, hs_transfer_close, hs_transfer_process,
	"transfer"
};
