/** netmill: ssl: http-client: decrypt response
2023, Simon Zolin */

#include <http-client/client.h>

static int slhc_resp_open(nml_http_client *c)
{
	if (NULL == ffvec_alloc(&c->recv.buf, 4096, 1)) {
		HC_WARN(c, "no memory");
		return NMLR_ERR;
	}
	return NMLR_OPEN;
}

static void slhc_resp_close(nml_http_client *c)
{
	ffvec_free(&c->recv.buf);
	ffvec_free(&c->recv.body);
}

static int slhc_resp_process(nml_http_client *c)
{
	if (c->recv_fin)
		return NMLR_ERR;

	if (c->input.len) {
		ffssl_conn_input(c->ssl.conn, c->input.len);
	}

	ffvec *buf;

	if (!c->response.status.len) {
		buf = &c->recv.buf;
		if (buf->len >= c->conf->receive.max_buf) {
			HC_ERR(c, "receive.max_buf limit reached");
			return NMLR_ERR;
		}

		if (0 == ffvec_unused(buf)
			&& NULL == ffvec_grow(buf, c->conf->receive.hdr_buf_size, 1)) {
			HC_ERR(c, "no memory");
			return NMLR_ERR;
		}

	} else {
		buf = &c->recv.body;
		if (!buf->cap
			&& NULL == ffvec_alloc(buf, c->conf->receive.body_buf_size, 1))
			return NMLR_ERR;
		buf->len = 0;
	}

	int r = ffssl_conn_read(c->ssl.conn, buf->ptr + buf->len, buf->cap - buf->len);
	switch (r) {
	case -FFSSL_WANTREAD:
		ffssl_conn_iobuf(c->ssl.conn, &c->ssl.recv_buffer);
		HC_EXTRALOG(c, "SSL read buf: 0x%p %L", c->ssl.recv_buffer.ptr, c->ssl.recv_buffer.len);
		return NMLR_BACK;

	case -FFSSL_WANTWRITE:
		HC_ERR(c, "SSL renegotiation");
		return NMLR_ERR;
	}

	if (r < 0) {
		char e[1000];
		HC_ERR(c, "ffssl_conn_read: %s", ffssl_error(-r, e, sizeof(e)));
		return NMLR_ERR;
	}

	buf->len += r;
	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

const nml_http_cl_component nml_htcl_ssl_resp = {
	slhc_resp_open, slhc_resp_close, slhc_resp_process,
	"ssl-resp"
};
