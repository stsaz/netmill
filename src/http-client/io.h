/** netmill: http-client: outbound connection I/O
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int http_cl_io_open(nml_http_client *c)
{
	if (NULL == ffvec_alloc(&c->io.buf, 4*1024, 1))
		return NMLF_ERR;
	c->io.filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void http_cl_io_close(nml_http_client *c)
{
	ffvec_free(&c->io.buf);
}

static void http_cl_io_ready_w(nml_http_client *c)
{
	c->w_pending = 0;
	c->conveyor.cur = c->io.filter_index;
	c->wake(c);
}

static int http_cl_io_send(nml_http_client *c)
{
	if (c->w_pending)
		return NMLF_SKIP;

	while (c->input.len) {
		ffiovec_set(&c->io.iov[0], c->input.ptr, c->input.len);
		c->io.iov_n = 1;
		int r = ffsock_sendv_async(c->sk, c->io.iov, c->io.iov_n, cl_kev_w(c));
		if (r < 0) {
			if (fferr_last() == FFSOCK_EINPROGRESS) {
				cl_dbglog(c, "send to server: in progress");
				c->w_pending = 1;
				cl_kev_w_async(c, http_cl_io_ready_w);
				return NMLF_ASYNC;
			}
			cl_syswarnlog(c, "socket write");
			return NMLF_ERR;
		}

		c->io.transferred_w += r;
		cl_dbglog(c, "sent to server: %u [%U]", r, c->io.transferred_w);
		ffstr_shift(&c->input, r);
	}

	if (c->req_complete) {
		int r = ffsock_fin(c->sk);
		cl_dbglog(c, "ffsock_fin: %d", r);
		return NMLF_DONE;
	}

	return NMLF_BACK;
}

static void http_cl_io_ready_r(nml_http_client *c)
{
	c->r_pending = 0;
	c->conveyor.cur = c->io.filter_index;
	c->wake(c);
}

static int http_cl_io_recv(nml_http_client *c)
{
	if (c->recv_fin)
		return NMLF_DONE;

	if (c->r_pending)
		return NMLF_SKIP;

	c->io.buf.len = 0;
	int r = ffsock_recv_async(c->sk, c->io.buf.ptr, c->io.buf.cap, cl_kev_r(c));
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			cl_dbglog(c, "receive from server: in progress");
			c->r_pending = 1;
			cl_kev_r_async(c, http_cl_io_ready_r);
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "socket read");
		return NMLF_ERR;
	}

	if (r == 0) {
		cl_dbglog(c, "server finished sending");
		c->recv_fin = 1;
		c->resp_complete = 1;
		return NMLF_DONE;
	}

	c->io.buf.len += r;
	c->io.transferred_r += r;
	cl_dbglog(c, "received from server: %u [%U]", r, c->io.transferred_r);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(c->io.buf.ptr, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

	ffstr_setstr(&c->output, &c->io.buf);
	return NMLF_FWD;
}

static int http_cl_io_process(nml_http_client *c)
{
	int rw = http_cl_io_send(c);
	if (rw == NMLF_ERR)
		return NMLF_ERR;

	int rr = http_cl_io_recv(c);
	if (rr == NMLF_ERR)
		return NMLF_ERR;

	if (!c->io_connect_result_passed) {
		c->io_connect_result_passed = 1;
		return NMLF_FWD;
	}

	if (rr == NMLF_FWD)
		return NMLF_FWD; // process data received from server
	if (rw == NMLF_BACK)
		return NMLF_BACK; // ask for more input data
	if (rr == NMLF_DONE && rw == NMLF_DONE)
		return NMLF_DONE;
	return NMLF_ASYNC;
}

const nml_http_cl_component nml_http_cl_io = {
	http_cl_io_open, http_cl_io_close, http_cl_io_process,
	"io"
};
