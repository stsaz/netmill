/** netmill: http-server: inbound HTTP client
2023, Simon Zolin */

#pragma once
#include <netmill.h>
#include <util/kq.h>
#include <util/range.h>
#include <util/http1.h>
#include <util/http1-status.h>
#include <util/conveyor-static.h>
#include <ffsys/dir.h>
#include <ffsys/timerqueue.h>
#include <ffbase/time.h>
#include <ffbase/vector.h>

#ifdef FF_WIN
typedef unsigned int uint;
#endif

/** Client-context logger */

#define cl_errlog(c, ...) \
	c->log(c->log_obj, NML_LOG_ERR, "http-sv", c->id, __VA_ARGS__)

#define cl_syswarnlog(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSWARN, "http-sv", c->id, __VA_ARGS__)

#define cl_warnlog(c, ...) \
	c->log(c->log_obj, NML_LOG_WARN, "http-sv", c->id, __VA_ARGS__)

#define cl_verblog(c, ...) \
do { \
	if (c->log_level >= NML_LOG_VERBOSE) \
		c->log(c->log_obj, NML_LOG_VERBOSE, "http-sv", c->id, __VA_ARGS__); \
} while (0)

#define cl_dbglog(c, ...) \
do { \
	if (c->log_level >= NML_LOG_DEBUG) \
		c->log(c->log_obj, NML_LOG_DEBUG, "http-sv", c->id, __VA_ARGS__); \
} while (0)

#define cl_extralog(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef cl_extralog
	#define cl_extralog(c, ...) \
	do { \
		if (c->log_level >= NML_LOG_DEBUG) \
			c->log(c->log_obj, NML_LOG_EXTRA, "http-sv", c->id, __VA_ARGS__); \
	} while (0)
#endif

/** Inbound client (connection) context */
struct nml_http_sv_conn {
	struct nml_http_server_conf *conf;

	uint log_level;
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *fmt, ...);
	void *log_obj;
	char id[12]; // "*ID"

	struct zzkevent *kev;
	ffsock sk;
	ffbyte peer_ip[16];
	ffushort peer_port;
	ffushort keep_alive_n;
	uint send_init :1;
	uint kq_attached :1;
	uint req_unprocessed_data :1;

	struct nml_conveyor conveyor;

	/** The current data passed between filters */
	ffstr input, output;

	// next data is cleared before each keep-alive/pipeline request

	ffuint64 start_time_msec;

	struct {
		ffvec req, body;
		nml_timer timer;
		ffuint64 transferred;
		uint filter_index;
	} recv;

	struct {
		range16 full, line, method, url, path, querystr, host, if_modified_since;
		ffstr unescaped_path;
	} req;

	void *proxy;

	struct {
		const struct nml_http_virtdoc *vdoc;
	} vspace;

	struct {
		ffvec buf;
	} index;

	struct {
		ffvec path;
		ffvec buf;
	} autoindex;

	struct {
		fffd f;
		ffvec buf;
		fffileinfo info;
		uint state;
	} file;

	ffstr acclog_buf;

	struct {
		ffuint64 cont_len;
	} transfer;

	struct {
		uint code;
		ffuint64 content_length;
		ffstr msg, location, content_type;
		ffstr last_modified;
		ffstr headers;
		ffvec buf;
	} resp;

	struct {
		ffiovec iov[3];
		uint iov_n;
		nml_timer timer;
		ffuint64 transferred;
		uint filter_index;
	} send;

	uint chain_going_back :1;
	uint chain_reset :1;
	uint recv_fin :1;
	uint req_method_head :1;
	uint req_complete :1;
	uint resp_connection_keepalive :1;
	uint resp_hdr_server_disable :1; // response: don't include Server header (e.g. for proxy response)
	uint resp_err :1;
	uint resp_done :1;
};

#define cl_req_hdr(c, range) \
	range16_tostr(&range, c->recv.req.ptr)

/** Set timer */
#define cl_timer(c, tmr, interval_sec, f, p) \
	c->conf->core.timer(c->conf->boss, tmr, interval_sec*1000, (void(*)(void*))f, p)

/** Disable timer */
#define cl_timer_stop(c, tmr) \
	c->conf->core.timer(c->conf->boss, tmr, 0, NULL, NULL)

/** Set error HTTP response status */
static inline void cl_resp_status(nml_http_sv_conn *c, enum HTTP_STATUS status)
{
	c->resp.code = http_status_code[status];
	if (c->resp.code == 400)
		c->resp_connection_keepalive = 0;
	ffstr_setz(&c->resp.msg, http_status_msg[status]);
	c->resp_err = 1;
}

/** Set success HTTP response status */
static inline void cl_resp_status_ok(nml_http_sv_conn *c, enum HTTP_STATUS status)
{
	c->resp.code = http_status_code[status];
	ffstr_setz(&c->resp.msg, http_status_msg[status]);
}

#define cl_kev_r(c)  &c->kev->rtask
#define cl_kev_w(c)  &c->kev->wtask
#define cl_kcq(c)  &c->kev->kcall
#define cl_kcq_active(c)  (c->kev->kcall.op != 0)

static inline int cl_async(nml_http_sv_conn *c)
{
	if (!c->kq_attached) {
		c->kq_attached = 1;
		if (0 != c->conf->core.kq_attach(c->conf->boss, c->sk, c->kev, c)) {
			c->conf->cl_destroy(c);
			return -1;
		}
	}
	return 0;
}
static inline int cl_async_r(nml_http_sv_conn *c, void *handler)
{
	c->kev->rhandler = handler;
	return cl_async(c);
}
static inline int cl_async_w(nml_http_sv_conn *c, void *handler)
{
	c->kev->whandler = handler;
	return cl_async(c);
}
