/** netmill: SOCKS Server: upstream connection I/O
2026, Simon Zolin */

#include <socks-server/conn.h>

static int sksv_io_open(nml_socks_sv_conn *c)
{
	if (c->resp_err)
		return NMLR_SKIP;

	c->io.filter_index = c->conveyor.cur;
	return NMLR_OPEN;
}

static void sksv_io_ready_w(nml_socks_sv_conn *c)
{
	c->w_pending = 0;
	c->conveyor.cur = c->io.filter_index;
	c->conf->cl_wake(c);
}

static int sksv_io_send(nml_socks_sv_conn *c)
{
	if (c->w_pending)
		return NMLR_SKIP;

	if (c->input.len) {
		c->io.data = c->input;
		c->input.len = 0;
	}

	while (c->io.data.len) {
		int r = ffsock_send_async(c->io.sk, c->io.data.ptr, c->io.data.len, SKSV_UP_KEV_W(c));
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				SKSV_DEBUG(c, "send to server: in progress");
				c->w_pending = 1;
				SKSV_UP_ASYNC_W(c, sksv_io_ready_w);
				return NMLR_ASYNC;
			}
			SKSV_SYSWARN(c, "socket write");
			return NMLR_ERR;
		}

		SKSV_DEBUG(c, "sent to server: %u", r);
		ffstr_shift(&c->io.data, r);
	}

	if (c->recv_fin) {
		int r = ffsock_fin(c->io.sk);
		SKSV_DEBUG(c, "ffsock_fin: %d", r);
		return NMLR_DONE;
	}

	return NMLR_BACK;
}

static void sksv_io_ready_r(nml_socks_sv_conn *c)
{
	c->r_pending = 0;
	c->conveyor.cur = c->io.filter_index;
	c->conf->cl_wake(c);
}

static int sksv_io_recv(nml_socks_sv_conn *c)
{
	if (c->upstream_fin)
		return NMLR_DONE;

	if (c->r_pending)
		return NMLR_SKIP;

	c->resp.buf.len = 0;
	int r = ffsock_recv_async(c->io.sk, c->resp.buf.ptr, c->resp.buf.cap, SKSV_UP_KEV_R(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			SKSV_DEBUG(c, "receive from server: in progress");
			c->r_pending = 1;
			SKSV_UP_ASYNC_R(c, sksv_io_ready_r);
			return NMLR_ASYNC;
		}
		SKSV_SYSWARN(c, "socket read");
		return NMLR_ERR;
	}

	if (r == 0) {
		SKSV_DEBUG(c, "server finished sending");
		c->upstream_fin = 1;
		return NMLR_DONE;
	}

	c->resp.buf.len += r;
	SKSV_DEBUG(c, "received from server: %u", r);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(c->resp.buf.ptr, n, FFMEM_PRINT_ZEROSPACE);
		SKSV_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, &c->resp.buf);
	return NMLR_FWD;
}

static int sksv_io_process(nml_socks_sv_conn *c)
{
	int rw = sksv_io_send(c);
	if (rw == NMLR_ERR)
		return NMLR_ERR;

	int rr = sksv_io_recv(c);
	if (rr == NMLR_ERR)
		return NMLR_ERR;

	if (!c->io_connect_result_passed) {
		c->io_connect_result_passed = 1;
		return NMLR_FWD;
	}

	if (rr == NMLR_FWD)
		return NMLR_FWD; // process data received from server
	if (rw == NMLR_BACK)
		return NMLR_BACK; // ask for more input data
	if (rr == NMLR_DONE && rw == NMLR_DONE)
		return NMLR_DONE;
	return NMLR_ASYNC;
}

const nml_socks_sv_component nml_sksv_io = {
	sksv_io_open, NULL, sksv_io_process,
	"io"
};
