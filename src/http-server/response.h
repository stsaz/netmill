/** netmill: http-server: prepare HTTP response
2022, Simon Zolin */

#include <http-server/client.h>

static int nml_resp_open(nml_http_sv_conn *c)
{
	if (NULL == ffvec_alloc(&c->resp.buf, c->conf->response.buf_size, 1)) {
		cl_syswarnlog(c, "no memory");
		return NMLF_ERR;
	}
	return NMLF_OPEN;
}

static void nml_resp_close(nml_http_sv_conn *c)
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
		if (r == 0)
			break;
		else if (r < 0)
			break;
		ffstr_shift(&h, r);

		if (r <= 2)
			break;

		const char *const *it;
		for (it = hdrs_skip;  *it != NULL;  it++) {
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

static int nml_resp_process(nml_http_sv_conn *c)
{
	char *d = (char*)c->resp.buf.ptr, *end = (char*)c->resp.buf.ptr + c->resp.buf.cap - 2;

	int r = http_resp_write(d, end - d, c->resp.code, c->resp.msg);
	if (r < 0) {
		cl_warnlog(c, "http_resp_write");
		return NMLF_FIN;
	}
	d += r;

	static const char* const hdrs_skip[] = {
		"host", "connection", "keepalive",
		// upgrade",
		"content-length", "transfer-encoding",
		"proxy-authenticate",
		NULL
	};
	r = headers_add(c->resp.headers, hdrs_skip, d, end - d);
	if (r < 0) {
		if (r == -2)
			cl_warnlog(c, "bad response headers");
		return NMLF_ERR;
	}
	d += r;

	if (c->resp.content_length != (ffuint64)-1) {
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

	cl_dbglog(c, "response: %S", &c->resp.buf);

	ffiovec_set(&c->send.iov[0], c->resp.buf.ptr, c->resp.buf.len);
	if (!c->req_method_head)
		ffiovec_set(&c->send.iov[1], c->input.ptr, c->input.len);
	else
		c->resp_done = 1;
	c->input.len = 0;
	c->send.iov_n = 2;
	return NMLF_DONE;
}

const struct nml_filter nml_filter_response = {
	(void*)nml_resp_open, (void*)nml_resp_close, (void*)nml_resp_process,
	"resp-prep"
};
