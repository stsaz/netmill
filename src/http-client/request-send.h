/** netmill: http-client: send HTTP request
2023, Simon Zolin */

#include <http-client/client.h>

static int hc_req_send_open(nml_http_client *c)
{
	c->send.filter_index = c->conveyor.cur;
	return NMLR_OPEN;
}

static void hc_req_send_close(nml_http_client *c)
{
	hc_timer_stop(c, &c->send.timer);
}

static void hc_req_send_expired(nml_http_client *c)
{
	HC_WARN(c, "send timeout");
	c->timeout = 1;
	c->wake(c);
}

static void hc_req_send_signal(nml_http_client *c)
{
	c->conveyor.cur = c->send.filter_index;
	c->wake(c);
}

static int hc_req_send_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLR_ERR;
	}

	if (c->input.len) {
		ffiovec_set(&c->send.iov[0], c->input.ptr, c->input.len);
		c->send.iov_n = 1;

	} else if (c->chain_going_back) {
		return NMLR_BACK;
	}

	while (c->send.iov_n != 0) {
		int r = ffsock_sendv_async(c->sk, c->send.iov, c->send.iov_n, HC_KEV_W(c));
		hc_timer_stop(c, &c->send.timer);
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				hc_timer(c, &c->send.timer, -(int)c->conf->send_timeout_msec, hc_req_send_expired, c);
				HC_ASYNC_W(c, hc_req_send_signal);
				return NMLR_ASYNC;
			}
			HC_SYSWARN(c, "socket writev");
			return NMLR_ERR;
		}

		HC_DEBUG(c, "ffsock_sendv: %u", r);
		c->send.transferred += r;

		if (!ffiovec_array_shift(c->send.iov, c->send.iov_n, r)) {
			c->send.iov_n = 0;
			break;
		}
	}

	if (c->req_complete)
		return NMLR_DONE;

	return NMLR_FWD;
}

const nml_http_cl_component nml_http_cl_send = {
	hc_req_send_open, hc_req_send_close, hc_req_send_process,
	"req-send"
};
