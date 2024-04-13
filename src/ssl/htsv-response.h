/** netmill: ssl: http-server: encrypt response data
2023, Simon Zolin */

#include <http-server/conn.h>

static int slhs_resp_open(nml_http_sv_conn *c)
{
	return NMLR_OPEN;
}

static void slhs_resp_close(nml_http_sv_conn *c)
{
	ffvec_free(&c->ssl.send_buf);
}

static int slhs_resp_process(nml_http_sv_conn *c)
{
	if (c->ssl.data_sent) {
		ffssl_conn_input(c->ssl_conn, c->ssl.data_sent);
		c->ssl.data_sent = 0;
	}

	FF_ASSERT(!c->input.len);

	if (c->ssl.out_data.len) {

	} else if (c->send.iov_n) {
		for (uint i = 0;  i < c->send.iov_n;  i++) {
			ffslice s = ffiovec_get(&c->send.iov[i]);
			ffvec_addstr(&c->ssl.send_buf, &s);
		}
		c->send.iov_n = 0;
		c->ssl.out_data = *(ffstr*)&c->ssl.send_buf;
		c->ssl.send_buf.len = 0;

	} else if (c->chain_going_back) {
		return NMLR_BACK;
	}

	FF_ASSERT(c->ssl.out_data.len);

	int r = ffssl_conn_write(c->ssl_conn, c->ssl.out_data.ptr, c->ssl.out_data.len);
	switch (r) {
	case -FFSSL_WANTWRITE:
		ffssl_conn_iobuf(c->ssl_conn, &c->output);
		HS_EXTRALOG(c, "SSL write data: 0x%p %L", c->output.ptr, c->output.len);
		return NMLR_FWD;

	case -FFSSL_WANTREAD:
		HS_ERR(c, "SSL renegotiation");
		return NMLR_ERR;
	}

	if (r < 0) {
		char e[1000];
		HS_ERR(c, "ffssl_conn_write: %s", ffssl_error(-r, e, sizeof(e)));
		return NMLR_ERR;
	}

	ffstr_shift(&c->ssl.out_data, r);
	FF_ASSERT(!c->ssl.out_data.len);

	if (c->resp_done)
		return NMLR_DONE;
	return NMLR_BACK;
}

const nml_http_sv_component nml_htsv_ssl_resp = {
	slhs_resp_open, slhs_resp_close, slhs_resp_process,
	"ssl-resp"
};
