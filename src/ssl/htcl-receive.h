/** netmill: ssl: http-client: receive TLS data
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int slhc_recv_open(nml_http_client *c)
{
	c->recv.filter_index = c->conveyor.cur;
	return NMLR_OPEN;
}

static void slhc_recv_close(nml_http_client *c)
{}

static void slhc_recv_expired(nml_http_client *c)
{
	HC_WARN(c, "receive timeout");
	c->timeout = 1;
	c->wake(c);
}

static void slhc_recv_signal(nml_http_client *c)
{
	c->conveyor.cur = c->recv.filter_index;
	c->wake(c);
}

static int slhc_recv_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLR_ERR;
	}

	ffstr buf = c->ssl.recv_buffer;

	if (!buf.len)
		return NMLR_FWD;

	int r = ffsock_recv_async(c->sk, buf.ptr, buf.len, HC_KEV_R(c));
	hc_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hc_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_msec, slhc_recv_expired, c);
			HC_ASYNC_R(c, slhc_recv_signal);
			HC_DEBUG(c, "receive from server: in progress");
			return NMLR_ASYNC;
		}
		HC_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}

	c->recv.transferred += r;
	HC_DEBUG(c, "received from server: %u [%U]", r, c->recv.transferred);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf.ptr, n, FFMEM_PRINT_ZEROSPACE);
		HC_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	c->ssl.recv_buffer.len = 0;

	if (r == 0) {
		c->recv_fin = 1;
		return NMLR_DONE;
	}

	ffstr_set(&c->output, buf.ptr, r);
	return NMLR_FWD;
}

const nml_http_cl_component nml_htcl_ssl_recv = {
	slhc_recv_open, slhc_recv_close, slhc_recv_process,
	"ssl-recv"
};
