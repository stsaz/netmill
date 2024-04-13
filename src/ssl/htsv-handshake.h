/** netmill: ssl: http-server: perform handshake
2023, Simon Zolin */

#include <http-server/conn.h>

static int slhs_hshake_open(nml_http_sv_conn *c)
{
	if (c->ssl_conn)
		return NMLR_SKIP; // the handshake has been completed already

	struct ffssl_opt o = {};
	int r;
	if ((r = ffssl_conn_create((ffssl_conn**)&c->ssl_conn, c->conf->ssl_ctx->ctx, FFSSL_ACCEPT | FFSSL_IOBUF, &o))) {
		char e[1000];
		HS_ERR(c, "ffssl_conn_create: %s", ffssl_error(r, e, sizeof(e)));
		return NMLR_ERR;
	}
	return NMLR_OPEN;
}

static void slhs_hshake_close(nml_http_sv_conn *c)
{
	if (c->chain_reset) return;

	ffssl_conn_free(c->ssl_conn);
	c->ssl_conn = NULL;
}

static void slhs_log_handshake_success(nml_http_sv_conn *c)
{
	ffssl_cert *cert = ffssl_conn_getptr(c->ssl_conn, FFSSL_PEER_CERT);
	if (!cert) {
		HS_DEBUG(c, "handshake complete.  proto: %s  cipher: %s"
			, ffssl_conn_getptr(c->ssl_conn, FFSSL_VERSION)
			, ffssl_conn_getptr(c->ssl_conn, FFSSL_CIPHER_NAME)
			);
		return;
	}

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

	HS_DEBUG(c, "handshake complete.  proto: %s  cipher: %s  peer-cert: subject: %s  issuer: %s  valid: %s/%s"
		, ffssl_conn_getptr(c->ssl_conn, FFSSL_VERSION)
		, ffssl_conn_getptr(c->ssl_conn, FFSSL_CIPHER_NAME)
		, info.subject, info.issuer
		, valid_from, valid_to);
}

static int slhs_hshake_process(nml_http_sv_conn *c)
{
	if (c->recv_fin)
		return NMLR_ERR;

	if (!c->ssl_handshake_logged) {
		c->ssl_handshake_logged = 1;
		HS_DEBUG(c, "performing SSL handshake...");
	}

	if (c->input.len) {
		ffssl_conn_input(c->ssl_conn, c->input.len);
	}

	if (c->ssl.data_sent) {
		ffssl_conn_input(c->ssl_conn, c->ssl.data_sent);
		c->ssl.data_sent = 0;
	}

	int r;
	switch (r = ffssl_conn_handshake(c->ssl_conn)) {
	case 0:
		break;

	case FFSSL_WANTWRITE:
		ffssl_conn_iobuf(c->ssl_conn, &c->output);
		HS_EXTRALOG(c, "SSL write data: 0x%p %L", c->output.ptr, c->output.len);
		return NMLR_FWD;

	case FFSSL_WANTREAD:
		ffssl_conn_iobuf(c->ssl_conn, &c->ssl.recv_buffer);
		HS_EXTRALOG(c, "SSL read buf: 0x%p %L", c->ssl.recv_buffer.ptr, c->ssl.recv_buffer.len);
		return NMLR_BACK;

	default: {
		char e[1000];
		HS_ERR(c, "ffssl_conn_handshake: %s", ffssl_error(r, e, sizeof(e)));
		return NMLR_ERR;
	}
	}

	if (ff_unlikely(c->conf->log_level >= NML_LOG_DEBUG))
		slhs_log_handshake_success(c);

	return NMLR_DONE;
}

const nml_http_sv_component nml_htsv_ssl_handshake = {
	slhs_hshake_open, slhs_hshake_close, slhs_hshake_process,
	"ssl-handshake"
};
