/** netmill: SOCKS Server: prepare response
2026, Simon Zolin */

#include <socks-server/conn.h>

static int sksv_resp_process(nml_socks_sv_conn *c)
{
	struct socks5_connect_host resp = {
		.status = c->resp.code,
		.addr_type = SOCKS5_ADDR_IPV4,
		.addr = {4, "\0\0\0\0"},
		.port = 0,
	};
	int r = socks5_connect_write(c->resp.buf.ptr, c->resp.buf.cap, &resp);
	NML_ASSERT(r > 0);
	c->resp_done = 1;
	ffstr_set(&c->output, c->resp.buf.ptr, r);
	return NMLR_DONE;
}

const nml_socks_sv_component nml_sksv_response = {
	NULL, NULL, sksv_resp_process,
	"resp"
};
