/** netmill: http-server: gzip compression
2024, Simon Zolin */

#include <http-server/conn.h>
#include <zlib/zlib-ff.h>

static int gzhs_write_open(nml_http_sv_conn *c)
{
	if (c->resp.content_length != ~0ULL
		&& c->resp.content_length < 1000)
		return NMLR_SKIP; // too small data

	ffstr ae = HS_REQUEST_DATA(c, c->req.accept_encoding), tag;
	while (ae.len) {
		ffstr_splitby(&ae, ',', &tag, &ae);
		ffstr_trimwhite(&tag);
		if (ffstr_eqz(&tag, "deflate"))
			goto open;
	}
	return NMLR_SKIP; // the client doesn't accept gzip

open:
	{
	struct z_conf zc = {
		.level = 3,
	};
	if (z_deflate_init(&c->gzip.zx, &zc)) {
		HS_ERR(c, "z_deflate_init");
		return NMLR_ERR;
	}
	ffvec_alloc(&c->gzip.buf, 16*1024, 1);
	}
	return NMLR_OPEN;
}

static void gzhs_write_close(nml_http_sv_conn *c)
{
	z_deflate_free(c->gzip.zx);
	ffvec_free(&c->gzip.buf);
}

static int gzhs_write_process(nml_http_sv_conn *c)
{
	if (c->resp_done) {
		c->resp_done = 0;
		c->gzip_finish = 1;
	}

	if (c->chain_going_back)
		c->input = c->gzip.qdata;

	uint zf = (!c->gzip_finish) ? 0 : Z_FINISH;
	size_t n = c->input.len;
	int r = z_deflate(c->gzip.zx, c->input.ptr, &n, c->gzip.buf.ptr, c->gzip.buf.cap, zf);
	HS_DEBUG(c, "z_deflate: %d %L->%L %xu"
		, r, c->input.len, n, zf);
	ffstr_shift(&c->input, n);
	c->gzip.qdata = c->input;
	if (r == 0) {
		return NMLR_BACK;

	} else if (r > 0) {

	} else if (r == Z_DONE) {
		c->resp_done = 1;
		return NMLR_DONE;

	} else {
		HS_ERR(c, "z_deflate: %s", z_errstr(c->gzip.zx));
		return NMLR_ERR;
	}

	if (!c->gzip_hdr) {
		c->gzip_hdr = 1;
		c->resp.content_length = ~0ULL;
		ffstr_setz(&c->resp.headers,
			"Content-Encoding: deflate\r\n"
			"Vary: Accept-Encoding\r\n"
			);
	}

	ffstr_set(&c->output, c->gzip.buf.ptr, r);
	return NMLR_FWD;
}

const nml_http_sv_component nml_http_sv_gzwrite = {
	gzhs_write_open, gzhs_write_close, gzhs_write_process,
	"gzip-write"
};
