/** netmill: SOCKS Server: send data to client
2026, Simon Zolin */

#include <socks-server/conn.h>

static int sksv_send_open(nml_socks_sv_conn *c)
{
	c->send.chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void sksv_send_close(nml_socks_sv_conn *c)
{
	sksv_timer_stop(c, &c->send.timer);
}

static void sksv_send_expired(nml_socks_sv_conn *c)
{
	SKSV_DEBUG(c, "send timeout");
	c->conf->cl_destroy(c);
}

static void sksv_send_ready(nml_socks_sv_conn *c)
{
	c->conveyor.cur = c->send.chain_pos;
	c->conf->cl_wake(c);
}

static int sksv_send_process(nml_socks_sv_conn *c)
{
	if (!c->send_init) {
		c->send_init = 1;
		if (ffsock_setopt(c->sk, IPPROTO_TCP, TCP_NODELAY, 1)) {
			SKSV_SYSWARN(c, "socket setopt(TCP_NODELAY)");
		}
	}

	if (c->input.len) {
		c->send.data = c->input;
		c->input.len = 0;
	}

	while (c->send.data.len) {
		int r = ffsock_send_async(c->sk, c->send.data.ptr, c->send.data.len, SKSV_KEV_W(c));
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				sksv_timer(c, &c->send.timer, -(int)c->conf->send.timeout_sec, sksv_send_expired, c);
				sksv_async_w(c, sksv_send_ready);
				return NMLR_ASYNC;
			}
			SKSV_SYSWARN(c, "socket write");
			return NMLR_ERR;
		}

		ffstr_shift(&c->send.data, r);
		c->send.transferred += r;
		SKSV_DEBUG(c, "sent to client: %u [%U]", r, c->send.transferred);
	}

	sksv_timer_stop(c, &c->send.timer);

	if (!c->req_complete)
		return (!c->auth_err) ? NMLR_DONE : NMLR_FIN; // auth complete

	if (c->upstream_fin) {
		int r = ffsock_fin(c->sk);
		SKSV_DEBUG(c, "ffsock_fin: %d", r);
		return NMLR_DONE;
	}

	return NMLR_BACK;
}

const nml_socks_sv_component nml_sksv_send = {
	sksv_send_open, sksv_send_close, sksv_send_process,
	"send"
};
