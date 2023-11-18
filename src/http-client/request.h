/** netmill: http-client: prepare outbound HTTP request
2023, Simon Zolin */

#include <http-client/client.h>

static int http_cl_req_open(nml_http_client *c)
{
	return NMLF_OPEN;
}

static void http_cl_req_close(nml_http_client *c)
{
	ffvec_free(&c->request.buf);
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

static int http_cl_req_process(nml_http_client *c)
{
	ffstr url = c->conf->path;
	if (c->conf->proxy_host.len)
		url.len += FFS_LEN("http://") + c->conf->host.len;

	uint cap = http_req_write(NULL, 0, c->conf->method, url, 0)
		+ http_hdr_write(NULL, 0, FFSTR_Z("Host"), c->conf->host)
		+ c->conf->headers.len * 2
		+ 2;
	if (NULL == ffvec_alloc(&c->request.buf, cap, 1)) {
		return NMLF_ERR;
	}
	char *d = c->request.buf.ptr;
	uint i = 0;

	int r;
	if (c->conf->proxy_host.len) {
		r = ffs_format(&d[i], cap - i, "%S http://%S%S HTTP/1.1\r\n"
			, &c->conf->method, &c->conf->host, &c->conf->path);
	} else {
		r = http_req_write(&d[i], cap - i, c->conf->method, c->conf->path, 0);
	}
	i += r;

	i += http_hdr_write(&d[i], cap - i, FFSTR_Z("Host"), c->conf->host);

	static const char* const hdrs_skip[] = {
		"host", /*"connection",*/ "keepalive",
		// "te", "upgrade",
		// "content-length", "transfer-encoding",
		"proxy-connection", "proxy-authorization",
		NULL
	};
	r = headers_add(c->conf->headers, hdrs_skip, &d[i], cap - i);
	if (r < 0) {
		if (r == -2)
			cl_warnlog(c, "bad request headers");
		return NMLF_ERR;
	}
	i += r;

	ffmem_copy(&d[i], "\r\n", 2);
	i += 2;

	c->request.buf.len = i;
	cl_dbglog(c, "request: %S", &c->request.buf);

	// ffstr_setstr(&c->output, &c->request.buf);
	ffiovec_set(&c->send.iov[0], c->request.buf.ptr, c->request.buf.len);
	ffiovec_set(&c->send.iov[1], c->input.ptr, c->input.len);
	c->send.iov_n = 2;
	return NMLF_DONE;
}

const nml_http_cl_component nml_http_cl_request = {
	http_cl_req_open, http_cl_req_close, http_cl_req_process,
	"req-prep"
};
