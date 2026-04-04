/** netmill: SOCKS Server: parse request
2026, Simon Zolin */

#include <socks-server/conn.h>

static void sksv_req_close(nml_socks_sv_conn *c)
{
	ffmem_free(c->resolve.hostname);
}

static int sksv_req_process(nml_socks_sv_conn *c)
{
	struct socks5_connect_host req = {};
	int r = socks5_connect_read(&req, c->input.ptr, c->input.len);
	if (r == 0) {
		return NMLR_BACK;
	} else if (r < 0) {
		SKSV_WARN(c, "socks5_connect_read");
		goto err;
	}

	if (req.cmd != SOCKS5_CMD_STREAM) {
		SKSV_WARN(c, "command not supported: %u", req.cmd);
		goto err;
	}

	ffip6 *ip6;
	switch (req.addr_type) {
	case SOCKS5_ADDR_IPV4:
		ip6 = ffvec_pushT(&c->resolve.addrs, ffip6);
		ffip6_v4mapped_set(ip6, (void*)req.addr.ptr);
		break;

	case SOCKS5_ADDR_IPV6:
		ip6 = ffvec_pushT(&c->resolve.addrs, ffip6);
		*ip6 = *(ffip6*)req.addr.ptr;
		break;

	case SOCKS5_ADDR_HOST:
		c->resolve.hostname = ffsz_dupstr(&req.addr);
		break;
	}

	c->connect.port = req.port;
	c->req_complete = 1;

	c->output = c->input;
	ffstr_shift(&c->output, r);
	return NMLR_DONE;

err:
	sksv_response_err(c, 1);
	return NMLR_ERR;
}

const nml_socks_sv_component nml_sksv_request = {
	NULL, sksv_req_close, sksv_req_process,
	"req"
};
