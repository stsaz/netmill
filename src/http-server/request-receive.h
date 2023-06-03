/** netmill: http-server: receive data
2022, Simon Zolin */

#include <http-server/client.h>
#include <ffbase/mem-print.h>

static int nml_recv_open(nml_http_sv_conn *c)
{
	c->recv.filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void nml_recv_close(nml_http_sv_conn *c)
{
	cl_timer_stop(c, &c->recv.timer);
	// ffvec_free(&c->recv.req); // handled by 'req-parse' filter
	ffvec_free(&c->recv.body);
}

static void nml_recv_read_expired(nml_http_sv_conn *c)
{
	cl_dbglog(c, "receive timeout");
	c->conf->cl_destroy(c);
}

static void nml_recv_ready(nml_http_sv_conn *c)
{
	c->conveyor.cur = c->recv.filter_index;
	c->conf->cl_wake(c);
}

static int nml_recv_body(nml_http_sv_conn *c)
{
	ffvec *buf = &c->recv.body;

	if (buf->cap == 0) {
		if (NULL == ffvec_alloc(buf, c->conf->recv_body.buf_size, 1)) {
			cl_errlog(c, "no memory");
			return NMLF_ERR;
		}
	}
	buf->len = 0;

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, cl_kev_r(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_timer(c, &c->recv.timer, -(int)c->conf->recv_body.timeout_sec, nml_recv_read_expired, c);
			cl_async_r(c, nml_recv_ready);
			cl_dbglog(c, "receive from client: in progress");
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "ffsock_recv");
		return NMLF_ERR;
	}
	cl_timer_stop(c, &c->recv.timer);

	if (r == 0) {
		cl_dbglog(c, "received FIN from client");
		c->recv_fin = 1;
		return NMLF_DONE;
	}

	buf->len += r;
	c->recv.transferred += r;
	cl_dbglog(c, "received from client: %u [%U]", r, c->recv.transferred);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, buf);
	return NMLF_FWD;
}

static int nml_recv_process(nml_http_sv_conn *c)
{
	if (c->resp_done)
		return NMLF_DONE;

	ffvec *buf = &c->recv.req;

	if (c->req_unprocessed_data) {
		goto fwd;
	}

	if (c->req.method.len) {
		return nml_recv_body(c);
	}

	if (buf->cap == 0) {
		if (NULL == ffvec_alloc(buf, c->conf->receive.buf_size, 1)) {
			cl_syswarnlog(c, "no memory");
			return NMLF_ERR;
		}
	}

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, cl_kev_r(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_sec, nml_recv_read_expired, c);
			cl_async_r(c, nml_recv_ready);
			cl_dbglog(c, "receive from client: in progress");
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "ffsock_recv");
		return NMLF_ERR;
	}
	cl_timer_stop(c, &c->recv.timer);

	if (r == 0) {
		cl_dbglog(c, "received FIN from client");
		if (buf->len == 0)
			return NMLF_FIN;

		c->recv_fin = 1;
		return NMLF_DONE;
	}

	buf->len += r;
	c->recv.transferred += r;
	cl_dbglog(c, "received from client: %u [%U]", r, c->recv.transferred);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

fwd:
	ffstr_setstr(&c->output, buf);
	return NMLF_FWD;
}

const struct nml_filter nml_filter_receive = {
	(void*)nml_recv_open, (void*)nml_recv_close, (void*)nml_recv_process,
	"req-recv"
};
