/** netmill: ssl: http-client: encrypt request data
2023, Simon Zolin */

#include <http-client/client.h>

static int slhc_req_open(nml_http_client *c)
{
	return NMLR_OPEN;
}

static void slhc_req_close(nml_http_client *c)
{}

static int slhc_req_process(nml_http_client *c)
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
		return NMLR_BACK;
	}

	int r = ffssl_conn_write(c->ssl.conn, c->ssl.out_data.ptr, c->ssl.out_data.len);
	switch (r) {
	case -FFSSL_WANTWRITE:
		ffssl_conn_iobuf(c->ssl.conn, &c->output);
		HC_EXTRALOG(c, "SSL write data: 0x%p %L", c->output.ptr, c->output.len);
		return NMLR_FWD;

	case -FFSSL_WANTREAD:
		HC_ERR(c, "SSL renegotiation");
		return NMLR_ERR;
	}

	if (r < 0) {
		char e[1000];
		HC_ERR(c, "ffssl_conn_write: %s", ffssl_error(-r, e, sizeof(e)));
		return NMLR_ERR;
	}

	ffstr_shift(&c->ssl.out_data, r);
	return NMLR_FWD;
}

const nml_http_cl_component nml_htcl_ssl_req = {
	slhc_req_open, slhc_req_close, slhc_req_process,
	"ssl-req"
};
