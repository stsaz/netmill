/** netmill: http-server: send data
2022, Simon Zolin */

#include <http-server/conn.h>

static int hs_send_open(nml_http_sv_conn *c)
{
	c->send.chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void hs_send_close(nml_http_sv_conn *c)
{
	hs_timer_stop(c, &c->send.timer);
}

static void hs_send_expired(nml_http_sv_conn *c)
{
	HS_DEBUG(c, "send timeout");
	c->conf->cl_destroy(c);
}

static void hs_send_ready(nml_http_sv_conn *c)
{
	c->conveyor.cur = c->send.chain_pos;
	c->conf->cl_wake(c);
}

static int hs_send_process(nml_http_sv_conn *c)
{
	if (!c->send_init) {
		c->send_init = 1;
		if (c->conf->send.tcp_nodelay
			&& 0 != ffsock_setopt(c->sk, IPPROTO_TCP, TCP_NODELAY, 1)) {
			HS_SYSWARN(c, "socket setopt(TCP_NODELAY)");
		}
	}

	if (c->input.len) {
		ffiovec_set(&c->send.iov[0], c->input.ptr, c->input.len);
		c->send.iov_n = 1;
		c->input.len = 0;
	}

	while (c->send.iov_n != 0) {
		int r = ffsock_sendv_async(c->sk, c->send.iov, c->send.iov_n, HS_KEV_W(c));
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				hs_timer(c, &c->send.timer, -(int)c->conf->send.timeout_sec, hs_send_expired, c);
				hs_async_w(c, hs_send_ready);
				return NMLR_ASYNC;
			}
			HS_SYSWARN(c, "socket writev");
			return NMLR_ERR;
		}

		c->send.transferred += r;
		HS_DEBUG(c, "sent to client: %u [%U]", r, c->send.transferred);

		if (!ffiovec_array_shift(c->send.iov, c->send.iov_n, r)) {
			c->send.iov_n = 0;
			break;
		}
	}

	hs_timer_stop(c, &c->send.timer);
	if (c->resp_done) {
		// if () {
		// 	int r = ffsock_fin(c->sk);
		// 	HS_DEBUG(c, "ffsock_fin: %d", r);
		// }
		return NMLR_DONE;
	}
	return NMLR_BACK;
}

const nml_http_sv_component nml_http_sv_send = {
	hs_send_open, hs_send_close, hs_send_process,
	"resp-send"
};
