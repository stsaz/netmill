/** netmill: http-client: SSL handshake filter
2023, Simon Zolin */

static int http_cl_ssl_hs_open(nml_http_client *c)
{
	if (c->ssl.conn)
		return NMLF_SKIP; // this connection is taken from cache and the handshake has been completed already

	struct ffssl_opt o = {};
	o.tls_hostname = c->resolve.hostname;
	int r;
	if ((r = ffssl_conn_create((ffssl_conn**)&c->ssl.conn, c->conf->ssl_ctx->ctx, FFSSL_CONNECT | FFSSL_IOBUF, &o))) {
		char e[1000];
		cl_errlog(c, "ffssl_conn_create: %s", ffssl_error(r, e, sizeof(e)));
		return NMLF_ERR;
	}
	return NMLF_OPEN;
}

static void http_cl_ssl_hs_close(nml_http_client *c)
{
	ffssl_conn_free(c->ssl.conn);  c->ssl.conn = NULL;
}

static void log_handshake_success(nml_http_client *c)
{
	ffssl_cert *cert = ffssl_conn_getptr(c->ssl.conn, FFSSL_PEER_CERT);
	struct ffssl_cert_info info = {};
	char valid_from[100], valid_to[100];
	ffssl_cert_info(cert, &info);
	ffssl_cert_free(cert);

	fftime t = {};
	ffdatetime dt;

	t.sec = info.valid_from + FFTIME_1970_SECONDS;
	fftime_split1(&dt, &t);
	valid_from[fftime_tostr1(&dt, valid_from, sizeof(valid_from), FFTIME_YMD)] = '\0';

	t.sec = info.valid_until + FFTIME_1970_SECONDS;
	fftime_split1(&dt, &t);
	valid_to[fftime_tostr1(&dt, valid_to, sizeof(valid_to), FFTIME_YMD)] = '\0';

	cl_dbglog(c, "handshake complete.  proto: %s  cipher: %s  peer-cert: subject: %s  issuer: %s  valid: %s/%s"
		, ffssl_conn_getptr(c->ssl.conn, FFSSL_VERSION)
		, ffssl_conn_getptr(c->ssl.conn, FFSSL_CIPHER_NAME)
		, info.subject, info.issuer
		, valid_from, valid_to);
}

static int http_cl_ssl_hs_process(nml_http_client *c)
{
	if (c->recv_fin)
		return NMLF_ERR;

	if (!c->ssl_handshake_logged) {
		c->ssl_handshake_logged = 1;
		cl_dbglog(c, "performing SSL handshake...");
	}

	if (c->input.len) {
		ffssl_conn_input(c->ssl.conn, c->input.len);
	}

	if (c->ssl.data_sent) {
		ffssl_conn_input(c->ssl.conn, c->ssl.data_sent);
		c->ssl.data_sent = 0;
	}

	int r;
	switch (r = ffssl_conn_handshake(c->ssl.conn)) {
	case 0:
		break;

	case FFSSL_WANTWRITE:
		ffssl_conn_iobuf(c->ssl.conn, &c->output);
		cl_extralog(c, "SSL write data: 0x%p %L", c->output.ptr, c->output.len);
		return NMLF_FWD;

	case FFSSL_WANTREAD:
		ffssl_conn_iobuf(c->ssl.conn, &c->ssl.recv_buffer);
		cl_extralog(c, "SSL read buf: 0x%p %L", c->ssl.recv_buffer.ptr, c->ssl.recv_buffer.len);
		return NMLF_BACK;

	default: {
		char e[1000];
		cl_errlog(c, "ffssl_conn_handshake: %s", ffssl_error(r, e, sizeof(e)));
		return NMLF_ERR;
	}
	}

	if (c->conf->log_level >= NML_LOG_DEBUG)
		log_handshake_success(c);

	return NMLF_DONE;
}

const nml_http_cl_component nml_http_cl_ssl_handshake = {
	http_cl_ssl_hs_open, http_cl_ssl_hs_close, http_cl_ssl_hs_process,
	"ssl-handshake"
};
