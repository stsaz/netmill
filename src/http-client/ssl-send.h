/** netmill: http-client: SSL data-send filter
2023, Simon Zolin */

static int nml_ssl_send_open(nml_http_client *c)
{
	c->send.filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void nml_ssl_send_close(nml_http_client *c)
{
	cl_timer_stop(c, &c->send.timer);
}

static void nml_ssl_send_expired(nml_http_client *c)
{
	cl_warnlog(c, "send timeout");
	c->timeout = 1;
	c->wake(c);
}

static void nml_ssl_send_signal(nml_http_client *c)
{
	c->conveyor.cur = c->send.filter_index;
	c->wake(c);
}

static int nml_ssl_send_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLF_ERR;
	}

	if (c->input.len) {
		ffiovec_set(&c->send.iov[0], c->input.ptr, c->input.len);
		c->send.iov_n = 1;

	} else if (c->chain_going_back) {
		return NMLF_BACK;

	} else {
		if (c->req_complete)
			return NMLF_DONE;
		return NMLF_FWD;
	}

	while (c->send.iov_n != 0) {
		int r = ffsock_sendv_async(c->sk, c->send.iov, c->send.iov_n, cl_kev_w(c));
		cl_timer_stop(c, &c->send.timer);
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				cl_timer(c, &c->send.timer, -(int)c->conf->send_timeout_msec, nml_ssl_send_expired, c);
				cl_kev_w_async(c, nml_ssl_send_signal);
				return NMLF_ASYNC;
			}
			cl_syswarnlog(c, "socket writev");
			return NMLF_ERR;
		}

		cl_dbglog(c, "ffsock_sendv: %u", r);
		c->send.transferred += r;
		c->ssl.data_sent += r;

		if (0 == ffiovec_array_shift(c->send.iov, c->send.iov_n, r)) {
			c->send.iov_n = 0;
			break;
		}
	}

	return NMLF_BACK;
}

const struct nml_filter nml_filter_ssl_send = {
	(void*)nml_ssl_send_open, (void*)nml_ssl_send_close, (void*)nml_ssl_send_process,
	"ssl-send"
};
