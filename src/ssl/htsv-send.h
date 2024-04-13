/** netmill: ssl: http-server: send TLS data
2023, Simon Zolin */

#include <http-server/conn.h>

static int slhs_send_open(nml_http_sv_conn *c)
{
	c->send.chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void slhs_send_close(nml_http_sv_conn *c)
{
	hs_timer_stop(c, &c->send.timer);
}

static void slhs_send_expired(nml_http_sv_conn *c)
{
	HS_WARN(c, "send timeout");
	c->conf->cl_destroy(c);
}

static void slhs_send_signal(nml_http_sv_conn *c)
{
	c->conveyor.cur = c->send.chain_pos;
	c->conf->cl_wake(c);
}

static int slhs_send_process(nml_http_sv_conn *c)
{
	if (c->input.len) {
		ffiovec_set(&c->send.iov[0], c->input.ptr, c->input.len);
		c->send.iov_n = 1;

	} else if (c->chain_going_back) {
		return NMLR_BACK;

	} else {
		if (c->req_complete)
			return NMLR_DONE;
		return NMLR_FWD;
	}

	while (c->send.iov_n != 0) {
		int r = ffsock_sendv_async(c->sk, c->send.iov, c->send.iov_n, HS_KEV_W(c));
		hs_timer_stop(c, &c->send.timer);
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				hs_timer(c, &c->send.timer, -(int)c->conf->send.timeout_sec, slhs_send_expired, c);
				hs_async_w(c, slhs_send_signal);
				return NMLR_ASYNC;
			}
			HS_SYSWARN(c, "socket writev");
			return NMLR_ERR;
		}

		HS_DEBUG(c, "ffsock_sendv: %u", r);
		c->send.transferred += r;
		c->ssl.data_sent += r;

		if (!ffiovec_array_shift(c->send.iov, c->send.iov_n, r)) {
			c->send.iov_n = 0;
			break;
		}
	}

	return NMLR_BACK;
}

const nml_http_sv_component nml_htsv_ssl_send = {
	slhs_send_open, slhs_send_close, slhs_send_process,
	"ssl-send"
};
