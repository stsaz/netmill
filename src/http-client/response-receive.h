/** netmill: http-client: receive HTTP response
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int hc_recv_open(nml_http_client *c)
{
	if (NULL == ffvec_alloc(&c->recv.buf, 4096, 1)) {
		HC_WARN(c, "no memory");
		return NMLR_ERR;
	}
	c->recv.filter_index = c->conveyor.cur;
	return NMLR_OPEN;
}

static void hc_recv_close(nml_http_client *c)
{
	hc_timer_stop(c, &c->recv.timer);
	ffvec_free(&c->recv.buf);
	ffvec_free(&c->recv.body);
}

static void hc_recv_expired(nml_http_client *c)
{
	HC_WARN(c, "receive timeout");
	c->timeout = 1;
	c->wake(c);
}

static void hc_recv_signal(nml_http_client *c)
{
	c->conveyor.cur = c->recv.filter_index;
	c->wake(c);
}

static int hc_recv_body(nml_http_client *c)
{
	ffvec *buf = &c->recv.body;

	if (!buf->cap)
		if (NULL == ffvec_alloc(buf, c->conf->receive.body_buf_size, 1))
			return NMLR_ERR;
	buf->len = 0;

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, HC_KEV_R(c));
	hc_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hc_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_msec, hc_recv_expired, c);
			HC_ASYNC_R(c, hc_recv_signal);
			HC_DEBUG(c, "receive from server: in progress");
			return NMLR_ASYNC;
		}
		HC_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}

	buf->len += r;
	c->recv.transferred += r;
	HC_DEBUG(c, "received from server: %u [%U]", r, c->recv.transferred);

	if (r == 0) {
		c->recv_fin = 1;
		return NMLR_DONE;
	}

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		HC_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

static int hc_recv_process(nml_http_client *c)
{
	if (c->timeout) {
		return NMLR_ERR;
	}

	if (c->response.status.len) {
		return hc_recv_body(c);
	}

	ffvec *buf = &c->recv.buf;

	if (buf->len >= c->conf->receive.max_buf) {
		HC_WARN(c, "receive.max_buf limit reached");
		return NMLR_ERR;
	}

	if (0 == ffvec_unused(buf)
		&& NULL == ffvec_grow(buf, c->conf->receive.hdr_buf_size, 1)) {
		HC_WARN(c, "no memory");
		return NMLR_ERR;
	}

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, HC_KEV_R(c));
	hc_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hc_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_msec, hc_recv_expired, c);
			HC_ASYNC_R(c, hc_recv_signal);
			HC_DEBUG(c, "receive from server: in progress");
			return NMLR_ASYNC;
		}
		HC_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}

	buf->len += r;
	c->recv.transferred += r;
	HC_DEBUG(c, "received from server: %u [%U]", r, c->recv.transferred);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		HC_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	if (r == 0) {
		c->recv_fin = 1;
		return NMLR_DONE;
	}

	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

const nml_http_cl_component nml_http_cl_recv = {
	hc_recv_open, hc_recv_close, hc_recv_process,
	"resp-recv"
};
