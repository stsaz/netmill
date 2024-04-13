/** netmill: http-server: write access log
2022, Simon Zolin */

#include <http-server/conn.h>
#include <util/ipaddr.h>

/* CLIENT_IP REQ_TOTAL "METHOD PATH VER" RESP_TOTAL "VER CODE MSG" REALTIME */
static int hs_accesslog_open(nml_http_sv_conn *c)
{
	ffstr dts;
	fftime end_time = c->conf->core.date(c->conf->boss, &dts);
	uint tms = end_time.sec*1000 + end_time.nsec/1000000 - c->start_time_msec;

	ffstr req_line = HS_REQUEST_DATA(c, c->req.line);
	uint cap = 500 + req_line.len;
	if (NULL == ffstr_alloc(&c->acclog_buf, cap)) {
		HS_WARN(c, "no memory");
		return NMLR_SKIP;
	}
	char *d = c->acclog_buf.ptr, *end = d + cap - 1;
	d += ffip46_tostr((void*)c->peer_ip, d, end - d);
	*d++ = '\t';
	d += ffs_format_r0(d, end - d, "%S \"%S\" %u %U %U %ums\n"
		, &dts
		, &req_line, (int)c->resp.code
		, c->recv.transferred, c->send.transferred
		, tms);
	c->acclog_buf.len = d - c->acclog_buf.ptr;
	return NMLR_OPEN;
}

static void hs_accesslog_close(nml_http_sv_conn *c)
{
	ffstr_free(&c->acclog_buf);
}

static int hs_accesslog_process(nml_http_sv_conn *c)
{
	if (HS_KCQ_ACTIVE(c))
		HS_DEBUG(c, "file write: completed");

	int r = fffile_write_async(c->conf->access_log_fd, c->acclog_buf.ptr, c->acclog_buf.len, HS_KCQ_CTX(c));
	if (r < 0) {
		if (fferr_last() == FFKCALL_EINPROGRESS) {
			HS_DEBUG(c, "file write: in progress");
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "file write");
		return NMLR_ERR;
	}

	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_accesslog = {
	hs_accesslog_open, hs_accesslog_close, hs_accesslog_process,
	"access-log"
};
