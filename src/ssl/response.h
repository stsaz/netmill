/** netmill: http-client: SSL response decryption filter
2023, Simon Zolin */

static int http_cl_ssl_resp_open(nml_http_client *c)
{
	if (NULL == ffvec_alloc(&c->recv.buf, 4096, 1)) {
		cl_warnlog(c, "no memory");
		return NMLF_ERR;
	}
	return NMLF_OPEN;
}

static void http_cl_ssl_resp_close(nml_http_client *c)
{
	ffvec_free(&c->recv.buf);
	ffvec_free(&c->recv.body);
}

static int http_cl_ssl_resp_process(nml_http_client *c)
{
	if (c->recv_fin)
		return NMLF_ERR;

	if (c->input.len) {
		ffssl_conn_input(c->ssl.conn, c->input.len);
	}

	ffvec *buf;

	if (!c->response.status.len) {
		buf = &c->recv.buf;
		if (buf->len >= c->conf->receive.max_buf) {
			cl_errlog(c, "receive.max_buf limit reached");
			return NMLF_ERR;
		}

		if (!ffvec_unused(buf)
			&& NULL == ffvec_grow(buf, c->conf->receive.hdr_buf_size, 1)) {
			cl_errlog(c, "no memory");
			return NMLF_ERR;
		}

	} else {
		buf = &c->recv.body;
		if (!buf->cap
			&& NULL == ffvec_alloc(buf, c->conf->receive.body_buf_size, 1))
			return NMLF_ERR;
		buf->len = 0;
	}

	int r;
	switch (r = ffssl_conn_read(c->ssl.conn, buf->ptr + buf->len, buf->cap - buf->len)) {
	case -FFSSL_WANTREAD:
		ffssl_conn_iobuf(c->ssl.conn, &c->ssl.recv_buffer);
		cl_extralog(c, "SSL read buf: 0x%p %L", c->ssl.recv_buffer.ptr, c->ssl.recv_buffer.len);
		return NMLF_BACK;

	case -FFSSL_WANTWRITE:
		cl_errlog(c, "SSL renegotiation");
		return NMLF_ERR;
	}

	if (r < 0) {
		char e[1000];
		cl_errlog(c, "ffssl_conn_read: %s", ffssl_error(-r, e, sizeof(e)));
		return NMLF_ERR;
	}

	buf->len += r;
	ffstr_setstr(&c->output, buf);
	return NMLF_FWD;
}

const nml_http_cl_component nml_http_cl_ssl_resp = {
	http_cl_ssl_resp_open, http_cl_ssl_resp_close, http_cl_ssl_resp_process,
	"ssl-resp"
};
