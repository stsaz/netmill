/** netmill: http-client: SSL data-receive filter
2023, Simon Zolin */

#include <ffbase/mem-print.h>

static int nml_ssl_recv_open(nml_http_client *c)
{
	c->recv.filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void nml_ssl_recv_close(nml_http_client *c)
{}

static void nml_ssl_recv_expired(nml_http_client *c)
{
	cl_warnlog(c, "receive timeout");
	c->timeout = 1;
	c->wake(c);
}

static void nml_ssl_recv_signal(nml_http_client *c)
{
	c->conveyor.cur = c->recv.filter_index;
	c->wake(c);
}

static int nml_ssl_recv_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLF_ERR;
	}

	ffstr buf = c->ssl.recv_buffer;

	if (!buf.len)
		return NMLF_FWD;

	int r = ffsock_recv_async(c->sk, buf.ptr, buf.len, cl_kev_r(c));
	cl_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_msec, nml_ssl_recv_expired, c);
			cl_kev_r_async(c, nml_ssl_recv_signal);
			cl_dbglog(c, "receive from server: in progress");
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "ffsock_recv");
		return NMLF_ERR;
	}

	c->recv.transferred += r;
	cl_dbglog(c, "received from server: %u [%U]", r, c->recv.transferred);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf.ptr, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

	c->ssl.recv_buffer.len = 0;

	if (r == 0) {
		c->recv_fin = 1;
		return NMLF_DONE;
	}

	ffstr_set(&c->output, buf.ptr, r);
	return NMLF_FWD;
}

const struct nml_filter nml_filter_ssl_recv = {
	(void*)nml_ssl_recv_open, (void*)nml_ssl_recv_close, (void*)nml_ssl_recv_process,
	"ssl-recv"
};
