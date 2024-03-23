/** netmill: http-client: SSL request encryption filter
2023, Simon Zolin */

static int http_cl_ssl_req_open(nml_http_client *c)
{
	return NMLF_OPEN;
}

static void http_cl_ssl_req_close(nml_http_client *c)
{}

static int http_cl_ssl_req_process(nml_http_client *c)
{
	if (c->ssl.data_sent) {
		ffssl_conn_input(c->ssl.conn, c->ssl.data_sent);
		c->ssl.data_sent = 0;
	}

	if (c->ssl.out_data.len) {

	} else if (c->send.iov_n) {
		FF_ASSERT(c->send.iov_n == 2
			&& !ffiovec_get(&c->send.iov[1]).len); // request body isn't supported
		c->send.iov_n = 0;
		ffslice s = ffiovec_get(&c->send.iov[0]);
		c->ssl.out_data = *(ffstr*)&s;

	} else if (c->chain_going_back) {
		return NMLF_BACK;
	}

	int r;
	switch (r = ffssl_conn_write(c->ssl.conn, c->ssl.out_data.ptr, c->ssl.out_data.len)) {
	case -FFSSL_WANTWRITE:
		ffssl_conn_iobuf(c->ssl.conn, &c->output);
		cl_extralog(c, "SSL write data: 0x%p %L", c->output.ptr, c->output.len);
		return NMLF_FWD;

	case -FFSSL_WANTREAD:
		cl_errlog(c, "SSL renegotiation");
		return NMLF_ERR;
	}

	if (r < 0) {
		char e[1000];
		cl_errlog(c, "ffssl_conn_write: %s", ffssl_error(-r, e, sizeof(e)));
		return NMLF_ERR;
	}

	ffstr_shift(&c->ssl.out_data, r);
	return NMLF_FWD;
}

const nml_http_cl_component nml_http_cl_ssl_req = {
	http_cl_ssl_req_open, http_cl_ssl_req_close, http_cl_ssl_req_process,
	"ssl-req"
};
