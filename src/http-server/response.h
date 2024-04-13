/** netmill: http-server: prepare HTTP response
2022, Simon Zolin */

#include <http-server/conn.h>

static int hs_resp_open(nml_http_sv_conn *c)
{
	if (NULL == ffvec_alloc(&c->resp.buf, c->conf->response.buf_size, 1)) {
		HS_SYSWARN(c, "no memory");
		return NMLR_ERR;
	}
	return NMLR_OPEN;
}

static void hs_resp_close(nml_http_sv_conn *c)
{
	ffvec_free(&c->resp.buf);
	ffstr_free(&c->resp.last_modified);
}

/**
Return N of bytes written;
 -1: not enough space
 -2: bad headers */
static int headers_add(ffstr h, const char* const *hdrs_skip, char *dst, uint cap)
{
	uint i = 0;
	ffstr name = {}, val = {};
	for (;;) {
		int r = http_hdr_parse(h, &name, &val);
		if (r < 0)
			return -2;
		ffstr_shift(&h, r);

		if (r <= 2)
			break;

		const char *const *it;
		for (it = hdrs_skip;  *it;  it++) {
			if (ffstr_ieqz(&name, *it))
				goto skip;
		}

		r = http_hdr_write(&dst[i], cap - i, name, val);
		if (r == 0)
			return -1;
		i += r;

	skip:
		;
	}
	return i;
}

static int hs_resp_process(nml_http_sv_conn *c)
{
	char *d = (char*)c->resp.buf.ptr, *end = (char*)c->resp.buf.ptr + c->resp.buf.cap - 2;

	int r = http_resp_write(d, end - d, c->resp.code, c->resp.msg);
	if (r < 0) {
		HS_WARN(c, "http_resp_write");
		return NMLR_FIN;
	}
	d += r;

	static const char* const hdrs_skip[] = {
		"connection",
		"content-length",
		"host",
		"keepalive",
		"proxy-authenticate",
		"transfer-encoding",
		// upgrade",
		NULL
	};
	r = headers_add(c->resp.headers, hdrs_skip, d, end - d);
	if (r < 0) {
		if (r == -2)
			HS_WARN(c, "bad response headers");
		return NMLR_ERR;
	}
	d += r;

	if (c->resp_transfer_encoding_chunked) {
		d += _ffs_copycz(d, end - d, "Transfer-Encoding: chunked\r\n");

	} else if (c->resp.content_length != ~0ULL) {
		d += _ffs_copycz(d, end - d, "Content-Length: ");
		d += ffs_fromint(c->resp.content_length, d, end - d, 0);
		d += _ffs_copycz(d, end - d, "\r\n");
	}

	ffstr val;
	if (c->resp.location.len)
		d += http_hdr_write(d, end - d, FFSTR_Z("Location"), c->resp.location);

	if (c->resp.last_modified.len)
		d += http_hdr_write(d, end - d, FFSTR_Z("Last-Modified"), c->resp.last_modified);

	if (c->resp.content_type.len)
		d += http_hdr_write(d, end - d, FFSTR_Z("Content-Type"), c->resp.content_type);

	if (c->conf->response.server_name.len && !c->resp_hdr_server_disable)
		d += http_hdr_write(d, end - d, FFSTR_Z("Server"), c->conf->response.server_name);

	ffstr_setz(&val, "keep-alive");
	if (!c->resp_connection_keepalive)
		ffstr_setz(&val, "close");
	d += http_hdr_write(d, end - d, FFSTR_Z("Connection"), val);

	*d++ = '\r';
	*d++ = '\n';
	c->resp.buf.len = d - (char*)c->resp.buf.ptr;

	HS_DEBUG(c, "response: %S", &c->resp.buf);

	if (!c->req_method_head) {
		if (c->send.iov_n) {
			// make space for the first element
			FF_ASSERT(c->send.iov_n < FF_COUNT(c->send.iov));
			c->send.iov[3] = c->send.iov[2];
			c->send.iov[2] = c->send.iov[1];
			c->send.iov[1] = c->send.iov[0];
			c->send.iov_n++;
		} else {
			ffiovec_set(&c->send.iov[1], c->input.ptr, c->input.len);
			c->send.iov_n = 2;
		}
	} else {
		c->send.iov_n = 1;
		c->resp_done = 1;
	}
	ffiovec_set(&c->send.iov[0], c->resp.buf.ptr, c->resp.buf.len);
	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_response = {
	hs_resp_open, hs_resp_close, hs_resp_process,
	"resp-prep"
};
