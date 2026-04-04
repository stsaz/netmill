/** netmill: SOCKS Server: write access log
2026, Simon Zolin */

#include <socks-server/conn.h>
#include <util/ipaddr.h>

/* CLIENT_IP DATE TARGET RESP_CODE REQ_TOTAL RESP_TOTAL REALTIME */
static int sksv_accesslog_open(nml_socks_sv_conn *c)
{
	ffstr dts;
	fftime end_time = c->conf->core.date(c->conf->boss, &dts);
	uint tms = end_time.sec*1000 + end_time.nsec/1000000 - c->start_time_msec;

	ffstr target = {};
	if (c->resolve.hostname)
		ffstr_setz(&target, c->resolve.hostname);
	uint cap = 500 + target.len;
	if (!ffstr_alloc(&c->acclog_buf, cap)) {
		SKSV_WARN(c, "no memory");
		return NMLR_SKIP;
	}
	char *d = c->acclog_buf.ptr, *end = d + cap - 1;
	d += ffip46_tostr((void*)c->peer_ip, d, end - d);
	*d++ = '\t';
	d += ffs_format_r0(d, end - d, "%S %S %u %U %U %ums\n"
		, &dts
		, &target, (int)c->resp.code
		, c->recv.transferred, c->send.transferred
		, tms);
	c->acclog_buf.len = d - c->acclog_buf.ptr;
	return NMLR_OPEN;
}

static void sksv_accesslog_close(nml_socks_sv_conn *c)
{
	ffstr_free(&c->acclog_buf);
}

static int sksv_accesslog_process(nml_socks_sv_conn *c)
{
	if (SKSV_KCQ_ACTIVE(c))
		SKSV_DEBUG(c, "file write: completed");

	int r = fffile_write_async(c->conf->access_log_fd, c->acclog_buf.ptr, c->acclog_buf.len, SKSV_KCQ_CTX(c));
	if (r < 0) {
		if (fferr_last() == FFKCALL_EINPROGRESS) {
			SKSV_DEBUG(c, "file write: in progress");
			return NMLR_ASYNC;
		}
		SKSV_SYSWARN(c, "file write");
		return NMLR_ERR;
	}

	return NMLR_FIN;
}

const nml_socks_sv_component nml_sksv_accesslog = {
	sksv_accesslog_open, sksv_accesslog_close, sksv_accesslog_process,
	"access-log"
};
