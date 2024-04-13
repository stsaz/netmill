/** netmill: http-client: outbound connection I/O
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int hc_io_open(nml_http_client *c)
{
	if (NULL == ffvec_alloc(&c->io.buf, 4*1024, 1))
		return NMLR_ERR;
	c->io.filter_index = c->conveyor.cur;
	return NMLR_OPEN;
}

static void hc_io_close(nml_http_client *c)
{
	ffvec_free(&c->io.buf);
}

static void hc_io_ready_w(nml_http_client *c)
{
	c->w_pending = 0;
	c->conveyor.cur = c->io.filter_index;
	c->wake(c);
}

static int hc_io_send(nml_http_client *c)
{
	if (c->w_pending)
		return NMLR_SKIP;

	while (c->input.len) {
		ffiovec_set(&c->io.iov[0], c->input.ptr, c->input.len);
		c->io.iov_n = 1;
		int r = ffsock_sendv_async(c->sk, c->io.iov, c->io.iov_n, HC_KEV_W(c));
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				HC_DEBUG(c, "send to server: in progress");
				c->w_pending = 1;
				HC_ASYNC_W(c, hc_io_ready_w);
				return NMLR_ASYNC;
			}
			HC_SYSWARN(c, "socket write");
			return NMLR_ERR;
		}

		c->io.transferred_w += r;
		HC_DEBUG(c, "sent to server: %u [%U]", r, c->io.transferred_w);
		ffstr_shift(&c->input, r);
	}

	if (c->req_complete) {
		int r = ffsock_fin(c->sk);
		HC_DEBUG(c, "ffsock_fin: %d", r);
		return NMLR_DONE;
	}

	return NMLR_BACK;
}

static void hc_io_ready_r(nml_http_client *c)
{
	c->r_pending = 0;
	c->conveyor.cur = c->io.filter_index;
	c->wake(c);
}

static int hc_io_recv(nml_http_client *c)
{
	if (c->recv_fin)
		return NMLR_DONE;

	if (c->r_pending)
		return NMLR_SKIP;

	c->io.buf.len = 0;
	int r = ffsock_recv_async(c->sk, c->io.buf.ptr, c->io.buf.cap, HC_KEV_R(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			HC_DEBUG(c, "receive from server: in progress");
			c->r_pending = 1;
			HC_ASYNC_R(c, hc_io_ready_r);
			return NMLR_ASYNC;
		}
		HC_SYSWARN(c, "socket read");
		return NMLR_ERR;
	}

	if (r == 0) {
		HC_DEBUG(c, "server finished sending");
		c->recv_fin = 1;
		c->resp_complete = 1;
		return NMLR_DONE;
	}

	c->io.buf.len += r;
	c->io.transferred_r += r;
	HC_DEBUG(c, "received from server: %u [%U]", r, c->io.transferred_r);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(c->io.buf.ptr, n, FFMEM_PRINT_ZEROSPACE);
		HC_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, &c->io.buf);
	return NMLR_FWD;
}

static int hc_io_process(nml_http_client *c)
{
	int rw = hc_io_send(c);
	if (rw == NMLR_ERR)
		return NMLR_ERR;

	int rr = hc_io_recv(c);
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

const nml_http_cl_component nml_http_cl_io = {
	hc_io_open, hc_io_close, hc_io_process,
	"io"
};
