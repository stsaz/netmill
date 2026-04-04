/** netmill: SOCKS Server: handle auth
2026, Simon Zolin */

#include <socks-server/conn.h>

static void sksv_auth_close(nml_socks_sv_conn *c)
{
	ffvec_free(&c->resp.buf);
}

static int sksv_auth_process(nml_socks_sv_conn *c)
{
	int r = socks5_cl_auth_find(c->input.ptr, c->input.len, SOCKS5_AUTH_NONE);
	if (!r) {
		return NMLR_BACK;
	} else if (r < 0) {
		SKSV_WARN(c, "socks5_cl_auth_find");
		return NMLR_ERR;
	} else if (r == 0xffff) {
		SKSV_VERBOSE(c, "no matching auth method");
		c->auth_err = 1;
	} else {
		ffslice_rm((ffslice*)&c->recv.buf, 0, r, 1);
	}

	if (!ffvec_alloc(&c->resp.buf, c->conf->send.buf_size, 1)) {
		SKSV_SYSWARN(c, "no memory");
		return NMLR_ERR;
	}
	char *p = c->resp.buf.ptr;
	*p++ = 5;
	*p++ = (!c->auth_err) ? SOCKS5_AUTH_NONE : SOCKS5_AUTH_NOMATCH;

	ffstr_set(&c->output, c->resp.buf.ptr, 2);
	return NMLR_DONE;
}

const nml_socks_sv_component nml_sksv_auth = {
	NULL, sksv_auth_close, sksv_auth_process,
	"auth"
};
