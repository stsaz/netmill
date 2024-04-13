/** netmill: http-server: receive data
2022, Simon Zolin */

#include <http-server/conn.h>
#include <ffbase/mem-print.h>

static int hs_recv_open(nml_http_sv_conn *c)
{
	c->recv.chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void hs_recv_close(nml_http_sv_conn *c)
{
	hs_timer_stop(c, &c->recv.timer);
	// ffvec_free(&c->recv.req) -- handled by 'req-parse' component
	ffvec_free(&c->recv.body);
}

static void hs_recv_read_expired(nml_http_sv_conn *c)
{
	HS_DEBUG(c, "receive timeout");
	c->conf->cl_destroy(c);
}

static void hs_recv_ready(nml_http_sv_conn *c)
{
	c->conveyor.cur = c->recv.chain_pos;
	c->conf->cl_wake(c);
}

static int hs_recv_body(nml_http_sv_conn *c)
{
	ffvec *buf = &c->recv.body;

	if (!buf->cap) {
		if (NULL == ffvec_alloc(buf, c->conf->recv_body.buf_size, 1)) {
			HS_ERR(c, "no memory");
			return NMLR_ERR;
		}
	}
	buf->len = 0;

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, HS_KEV_R(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hs_timer(c, &c->recv.timer, -(int)c->conf->recv_body.timeout_sec, hs_recv_read_expired, c);
			hs_async_r(c, hs_recv_ready);
			HS_DEBUG(c, "receive from client: in progress");
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}
	hs_timer_stop(c, &c->recv.timer);

	if (r == 0) {
		HS_DEBUG(c, "received FIN from client");
		c->recv_fin = 1;
		return NMLR_DONE;
	}

	buf->len += r;
	c->recv.transferred += r;
	HS_DEBUG(c, "received from client: %u [%U]", r, c->recv.transferred);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		HS_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

static int hs_recv_process(nml_http_sv_conn *c)
{
	if (c->resp_done)
		return NMLR_DONE;

	ffvec *buf = &c->recv.req;

	if (c->req_unprocessed_data) {
		goto fwd;
	}

	if (c->req.method.len) {
		return hs_recv_body(c);
	}

	if (!buf->cap) {
		if (NULL == ffvec_alloc(buf, c->conf->receive.buf_size, 1)) {
			HS_SYSWARN(c, "no memory");
			return NMLR_ERR;
		}
	}

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, HS_KEV_R(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hs_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_sec, hs_recv_read_expired, c);
			hs_async_r(c, hs_recv_ready);
			HS_DEBUG(c, "receive from client: in progress");
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}
	hs_timer_stop(c, &c->recv.timer);

	if (r == 0) {
		HS_DEBUG(c, "received FIN from client");
		if (!buf->len)
			return NMLR_FIN;

		c->recv_fin = 1;
		return NMLR_DONE;
	}

	buf->len += r;
	c->recv.transferred += r;
	HS_DEBUG(c, "received from client: %u [%U]", r, c->recv.transferred);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		HS_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

fwd:
	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

const nml_http_sv_component nml_http_sv_receive = {
	hs_recv_open, hs_recv_close, hs_recv_process,
	"req-recv"
};
