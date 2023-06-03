/** netmill: http-server: send data
2022, Simon Zolin */

#include <http-server/client.h>

static int nml_send_open(nml_http_sv_conn *c)
{
	c->send.filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void nml_send_close(nml_http_sv_conn *c)
{
	cl_timer_stop(c, &c->send.timer);
}

static void nml_send_expired(nml_http_sv_conn *c)
{
	cl_dbglog(c, "send timeout");
	c->conf->cl_destroy(c);
}

static void nml_send_ready(nml_http_sv_conn *c)
{
	c->conveyor.cur = c->send.filter_index;
	c->conf->cl_wake(c);
}

static int nml_send_process(nml_http_sv_conn *c)
{
	if (!c->send_init) {
		c->send_init = 1;
		if (c->conf->send.tcp_nodelay
			&& 0 != ffsock_setopt(c->sk, IPPROTO_TCP, TCP_NODELAY, 1)) {
			cl_syswarnlog(c, "socket setopt(TCP_NODELAY)");
		}
	}

	if (c->input.len != 0) {
		ffiovec_set(&c->send.iov[0], c->input.ptr, c->input.len);
		c->send.iov_n = 1;
		c->input.len = 0;
	}

	while (c->send.iov_n != 0) {
		int r = ffsock_sendv_async(c->sk, c->send.iov, c->send.iov_n, cl_kev_w(c));
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				cl_timer(c, &c->send.timer, -(int)c->conf->send.timeout_sec, nml_send_expired, c);
				cl_async_w(c, nml_send_ready);
				return NMLF_ASYNC;
			}
			cl_syswarnlog(c, "socket writev");
			return NMLF_ERR;
		}

		c->send.transferred += r;
		cl_dbglog(c, "sent to client: %u [%U]", r, c->send.transferred);

		if (ffiovec_array_shift(c->send.iov, c->send.iov_n, r) == 0) {
			c->send.iov_n = 0;
			break;
		}
	}

	cl_timer_stop(c, &c->send.timer);
	if (c->resp_done) {
		// if () {
		// 	int r = ffsock_fin(c->sk);
		// 	cl_dbglog(c, "ffsock_fin: %d", r);
		// }
		return NMLF_DONE;
	}
	return NMLF_BACK;
}

const struct nml_filter nml_filter_send = {
	(void*)nml_send_open, (void*)nml_send_close, (void*)nml_send_process,
	"resp-send"
};
