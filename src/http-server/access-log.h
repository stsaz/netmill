/** netmill: http-server: write access log
2022, Simon Zolin */

#include <http-server/client.h>
#include <util/ipaddr.h>
#include <FFOS/std.h>

/* CLIENT_IP REQ_TOTAL "METHOD PATH VER" RESP_TOTAL "VER CODE MSG" REALTIME */
static int nml_accesslog_open(nml_http_sv_conn *c)
{
	ffstr dts;
	fftime end_time = c->conf->core.date(c->conf->boss, &dts);
	uint tms = end_time.sec*1000 + end_time.nsec/1000000 - c->start_time_msec;

	ffstr req_line;
	req_line = cl_req_hdr(c, c->req.line);

	ffuint cap = 500 + req_line.len;
	if (NULL == ffstr_alloc(&c->acclog_buf, cap)) {
		cl_warnlog(c, "no memory");
		return NMLF_SKIP;
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
	return NMLF_OPEN;
}

static void nml_accesslog_close(nml_http_sv_conn *c)
{
	ffstr_free(&c->acclog_buf);
}

static int nml_accesslog_process(nml_http_sv_conn *c)
{
	if (cl_kcq_active(c))
		cl_dbglog(c, "fffile_write: completed");

	int r = fffile_write_async(ffstderr, c->acclog_buf.ptr, c->acclog_buf.len, cl_kcq(c));
	if (r < 0) {
		if (fferr_last() == FFKCALL_EINPROGRESS) {
			cl_dbglog(c, "fffile_write: in progress");
			return NMLF_ASYNC;
		}
		cl_syswarnlog(c, "fffile_write");
		return NMLF_ERR;
	}

	return NMLF_DONE;
}

const struct nml_filter nml_filter_accesslog = {
	(void*)nml_accesslog_open, (void*)nml_accesslog_close, (void*)nml_accesslog_process,
	"access-log"
};
