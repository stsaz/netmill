/** netmill: SOCKS Server: receive data from client
2026, Simon Zolin */

#include <socks-server/conn.h>
#include <ffbase/mem-print.h>

static int sksv_recv_open(nml_socks_sv_conn *c)
{
	c->recv.chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void sksv_recv_close(nml_socks_sv_conn *c)
{
	sksv_timer_stop(c, &c->recv.timer);
	ffvec_free(&c->recv.buf);
}

static void sksv_recv_read_expired(nml_socks_sv_conn *c)
{
	SKSV_DEBUG(c, "receive timeout");
	c->conf->cl_destroy(c);
}

static void sksv_recv_ready(nml_socks_sv_conn *c)
{
	c->conveyor.cur = c->recv.chain_pos;
	c->conf->cl_wake(c);
}

static int sksv_recv_process(nml_socks_sv_conn *c)
{
	ffvec *buf = &c->recv.buf;

	if (!buf->cap) {
		if (!ffvec_alloc(buf, c->conf->receive.buf_size, 1)) {
			SKSV_SYSWARN(c, "no memory");
			return NMLR_ERR;
		}
	}

	if (c->req_complete)
		buf->len = 0;

	int r = ffsock_recv_async(c->sk, buf->ptr + buf->len, buf->cap - buf->len, SKSV_KEV_R(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			sksv_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_sec, sksv_recv_read_expired, c);
			sksv_async_r(c, sksv_recv_ready);
			SKSV_DEBUG(c, "receive from client: in progress");
			return NMLR_ASYNC;
		}
		SKSV_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}
	sksv_timer_stop(c, &c->recv.timer);

	if (r == 0) {
		SKSV_DEBUG(c, "received FIN from client");
		c->recv_fin = 1;
		return NMLR_DONE;
	}

	buf->len += r;
	c->recv.transferred += r;
	SKSV_DEBUG(c, "received from client: %u [%U]", r, c->recv.transferred);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf->ptr + buf->len - r, n, FFMEM_PRINT_ZEROSPACE);
		SKSV_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, buf);
	return NMLR_FWD;
}

const nml_socks_sv_component nml_sksv_receive = {
	sksv_recv_open, sksv_recv_close, sksv_recv_process,
	"recv"
};
