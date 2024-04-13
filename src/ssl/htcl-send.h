/** netmill: ssl: http-client: send TLS data
2023, Simon Zolin */

#include <http-client/client.h>

static int slhc_send_open(nml_http_client *c)
{
	c->send.filter_index = c->conveyor.cur;
	return NMLR_OPEN;
}

static void slhc_send_close(nml_http_client *c)
{
	hc_timer_stop(c, &c->send.timer);
}

static void slhc_send_expired(nml_http_client *c)
{
	HC_WARN(c, "send timeout");
	c->timeout = 1;
	c->wake(c);
}

static void slhc_send_signal(nml_http_client *c)
{
	c->conveyor.cur = c->send.filter_index;
	c->wake(c);
}

static int slhc_send_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLR_ERR;
	}

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
		int r = ffsock_sendv_async(c->sk, c->send.iov, c->send.iov_n, HC_KEV_W(c));
		hc_timer_stop(c, &c->send.timer);
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				hc_timer(c, &c->send.timer, -(int)c->conf->send_timeout_msec, slhc_send_expired, c);
				HC_ASYNC_W(c, slhc_send_signal);
				return NMLR_ASYNC;
			}
			HC_SYSWARN(c, "socket writev");
			return NMLR_ERR;
		}

		HC_DEBUG(c, "ffsock_sendv: %u", r);
		c->send.transferred += r;
		c->ssl.data_sent += r;

		if (!ffiovec_array_shift(c->send.iov, c->send.iov_n, r)) {
			c->send.iov_n = 0;
			break;
		}
	}

	return NMLR_BACK;
}

const nml_http_cl_component nml_htcl_ssl_send = {
	slhc_send_open, slhc_send_close, slhc_send_process,
	"ssl-send"
};
