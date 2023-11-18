/** netmill: http-client: receive HTTP response
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int http_cl_recv_open(nml_http_client *c)
{
	if (NULL == ffvec_alloc(&c->recv.buf, 4096, 1)) {
		cl_warnlog(c, "no memory");
		return NMLF_ERR;
	}
	c->recv.filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void http_cl_recv_close(nml_http_client *c)
{
	cl_timer_stop(c, &c->recv.timer);
	ffvec_free(&c->recv.buf);
	ffvec_free(&c->recv.body);
}

static void http_cl_recv_expired(nml_http_client *c)
{
	cl_warnlog(c, "receive timeout");
	c->timeout = 1;
	c->wake(c);
}

static void http_cl_recv_signal(nml_http_client *c)
{
	c->conveyor.cur = c->recv.filter_index;
	c->wake(c);
}

static int http_cl_recv_body(nml_http_client *c)
{
	ffvec *buf = &c->recv.body;

	if (!buf->cap)
		if (NULL == ffvec_alloc(buf, c->conf->receive.body_buf_size, 1))
			return NMLF_ERR;
	buf->len = 0;

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, cl_kev_r(c));
	cl_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_msec, http_cl_recv_expired, c);
			cl_kev_r_async(c, http_cl_recv_signal);
			cl_dbglog(c, "receive from server: in progress");
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "ffsock_recv");
		return NMLF_ERR;
	}

	buf->len += r;
	c->recv.transferred += r;
	cl_dbglog(c, "received from server: %u [%U]", r, c->recv.transferred);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

	if (r == 0) {
		c->recv_fin = 1;
		return NMLF_DONE;
	}

	ffstr_setstr(&c->output, buf);
	return NMLF_FWD;
}

static int http_cl_recv_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLF_ERR;
	}

	if (c->response.status.len) {
		return http_cl_recv_body(c);
	}

	ffvec *buf = &c->recv.buf;

	if (buf->len >= c->conf->receive.max_buf) {
		cl_warnlog(c, "receive.max_buf limit reached");
		return NMLF_ERR;
	}

	if (!ffvec_unused(buf)
		&& NULL == ffvec_grow(buf, c->conf->receive.hdr_buf_size, 1)) {
		cl_warnlog(c, "no memory");
		return NMLF_ERR;
	}

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, cl_kev_r(c));
	cl_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_msec, http_cl_recv_expired, c);
			cl_kev_r_async(c, http_cl_recv_signal);
			cl_dbglog(c, "receive from server: in progress");
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "ffsock_recv");
		return NMLF_ERR;
	}

	buf->len += r;
	c->recv.transferred += r;
	cl_dbglog(c, "received from server: %u [%U]", r, c->recv.transferred);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

	if (r == 0) {
		c->recv_fin = 1;
		return NMLF_DONE;
	}

	ffstr_setstr(&c->output, buf);
	return NMLF_FWD;
}

const nml_http_cl_component nml_http_cl_recv = {
	http_cl_recv_open, http_cl_recv_close, http_cl_recv_process,
	"resp-recv"
};
