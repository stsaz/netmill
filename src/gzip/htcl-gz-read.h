/** netmill: http-client: gzip decompression
2024, Simon Zolin */

#include <http-client/client.h>
#include <zlib/zlib-ff.h>

static int gzhc_read_open(nml_http_client *c)
{
	ffstr ce = HC_RESPONSE_DATA(c, c->response.content_encoding);
	if (!ffstr_ieqz(&ce, "gzip"))
		return NMLR_SKIP;

	if (z_inflate_init(&c->gzip.zx, NULL)) {
		HC_ERR(c, "z_inflate_init");
		return NMLR_ERR;
	}
	ffvec_alloc(&c->gzip.buf, 16*1024, 1);
	return NMLR_OPEN;
}

static void gzhc_read_close(nml_http_client *c)
{
	z_inflate_free(c->gzip.zx);
	ffvec_free(&c->gzip.buf);
}

static int gzhc_read_process(nml_http_client *c)
{
	size_t n = c->input.len;

	if (c->chain_going_back)
		c->input = c->gzip.qdata;

	int r = z_inflate(c->gzip.zx, c->input.ptr, &n, c->gzip.buf.ptr, c->gzip.buf.cap, 0);
	HC_DEBUG(c, "z_inflate: %d %L->%L"
		, r, c->input.len, n);
	ffstr_shift(&c->input, n);
	c->gzip.qdata = c->input;
	if (r == 0) {
		return NMLR_BACK;

	} else if (r > 0) {

	} else if (r == Z_DONE) {
		return NMLR_DONE;

	} else {
		HC_ERR(c, "z_inflate: %s", z_errstr(c->gzip.zx));
		return NMLR_ERR;
	}

	ffstr_set(&c->output, c->gzip.buf.ptr, r);
	return NMLR_FWD;
}

static const nml_http_cl_component nml_http_cl_gzread = {
	gzhc_read_open, gzhc_read_close, gzhc_read_process,
	"gzip-read"
};
