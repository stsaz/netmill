/** netmill: ssl: http-server: receive TLS data
2023, Simon Zolin */

#include <http-server/conn.h>
#include <ffbase/mem-print.h>

static int slhs_recv_open(nml_http_sv_conn *c)
{
	c->recv.chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void slhs_recv_expired(nml_http_sv_conn *c)
{
	HS_WARN(c, "receive timeout");
	c->conf->cl_destroy(c);
}

static void slhs_recv_signal(nml_http_sv_conn *c)
{
	c->conveyor.cur = c->recv.chain_pos;
	c->conf->cl_wake(c);
}

static int slhs_recv_process(nml_http_sv_conn *c)
{
	ffstr buf = c->ssl.recv_buffer;
	if (!buf.len)
		return NMLR_FWD;

	int r = ffsock_recv_async(c->sk, buf.ptr, buf.len, HS_KEV_R(c));
	hs_timer_stop(c, &c->recv.timer);
	if (r < 0) {
		if (fferr_last() == FFSOCK_EINPROGRESS) {
			hs_timer(c, &c->recv.timer, -(int)c->conf->receive.timeout_sec, slhs_recv_expired, c);
			hs_async_r(c, slhs_recv_signal);
			HS_DEBUG(c, "receive from client: in progress");
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "ffsock_recv");
		return NMLR_ERR;
	}

	if (r == 0) {
		HS_DEBUG(c, "received FIN from client");
		if (!c->recv.req.len)
			return NMLR_FIN;

		c->recv_fin = 1;
		return NMLR_DONE;
	}

	c->recv.transferred += r;
	HS_DEBUG(c, "received from client: %u [%U]", r, c->recv.transferred);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(r, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(buf.ptr, n, FFMEM_PRINT_ZEROSPACE);
		HS_DEBUG(c, "\n%S", &s);
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

const nml_http_sv_component nml_htsv_ssl_recv = {
	slhs_recv_open, NULL, slhs_recv_process,
	"ssl-recv"
};
