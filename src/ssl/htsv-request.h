/** netmill: ssl: http-client: decrypt request
2023, Simon Zolin */

#include <http-server/conn.h>

static int slhs_req_open(nml_http_sv_conn *c)
{
	return NMLR_OPEN;
}

static void slhs_req_close(nml_http_sv_conn *c)
{
	// ffvec_free(&c->recv.req) -- handled by 'req-parse' component
	ffvec_free(&c->recv.body);
}

static int slhs_req_process(nml_http_sv_conn *c)
{
	if (c->resp_done)
		return NMLR_DONE;

	ffvec *buf = &c->recv.req;

	if (c->req_unprocessed_data) {
		goto fwd;
	}

	if (c->input.len) {
		ffssl_conn_input(c->ssl_conn, c->input.len);
	}

	if (!c->req.method.len) {
		if (!buf->cap) {
			if (NULL == ffvec_alloc(buf, c->conf->receive.buf_size, 1)) {
				HS_SYSWARN(c, "no memory");
				return NMLR_ERR;
			}
		}

	} else {
		buf = &c->recv.body;
		if (!buf->cap
			&& NULL == ffvec_alloc(buf, c->conf->recv_body.buf_size, 1)) {
			HS_ERR(c, "no memory");
			return NMLR_ERR;
		}
		buf->len = 0;
	}

	int r = ffssl_conn_read(c->ssl_conn, buf->ptr + buf->len, buf->cap - buf->len);
	switch (r) {
	case -FFSSL_WANTREAD:
		ffssl_conn_iobuf(c->ssl_conn, &c->ssl.recv_buffer);
		HS_EXTRALOG(c, "SSL read buf: 0x%p %L", c->ssl.recv_buffer.ptr, c->ssl.recv_buffer.len);
		return NMLR_BACK;

	case -FFSSL_WANTWRITE:
		HS_ERR(c, "SSL renegotiation");
		return NMLR_ERR;
	}

	if (r < 0) {
		char e[1000];
		HS_ERR(c, "ffssl_conn_read: %s", ffssl_error(-r, e, sizeof(e)));
		return NMLR_ERR;
	}

	buf->len += r;

fwd:
	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

const nml_http_sv_component nml_htsv_ssl_req = {
	slhs_req_open, slhs_req_close, slhs_req_process,
	"ssl-req"
};
