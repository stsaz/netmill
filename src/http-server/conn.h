/** netmill: http-server: HTTP connection data
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

/** Client-context logger */

#define HS_ERR(c, ...) \
	c->log(c->log_obj, NML_LOG_ERR, "http-sv", c->id, __VA_ARGS__)

#define HS_SYSWARN(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSWARN, "http-sv", c->id, __VA_ARGS__)

#define HS_WARN(c, ...) \
	c->log(c->log_obj, NML_LOG_WARN, "http-sv", c->id, __VA_ARGS__)

#define HS_VERBOSE(c, ...) \
do { \
	if (c->log_level >= NML_LOG_VERBOSE) \
		c->log(c->log_obj, NML_LOG_VERBOSE, "http-sv", c->id, __VA_ARGS__); \
} while (0)

#define HS_DEBUG(c, ...) \
do { \
	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) \
		c->log(c->log_obj, NML_LOG_DEBUG, "http-sv", c->id, __VA_ARGS__); \
} while (0)

#define HS_EXTRALOG(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef HS_EXTRALOG
	#define HS_EXTRALOG(c, ...) \
	do { \
		if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) \
			c->log(c->log_obj, NML_LOG_EXTRA, "http-sv", c->id, __VA_ARGS__); \
	} while (0)
#endif

typedef struct z_ctx z_ctx;

/** Inbound client (connection) context */
struct nml_http_sv_conn {
	struct nml_http_server_conf *conf;

	uint log_level;
	char id[12]; // "*ID"
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *fmt, ...);
	void *log_obj;

	struct zzkevent *kev;
	ffsock sk;
	u_char peer_ip[16];
	ffushort peer_port;
	ffushort keep_alive_n;
	uint send_init :1;
	uint kq_attached :1;
	uint req_unprocessed_data :1;

	struct nml_conveyor conveyor;

	/** The current data passed between components */
	ffstr input, output;

	void *ssl_conn; // ffssl_conn

	// next data is cleared before each keep-alive/pipeline request

	uint64 start_time_msec;

	struct {
		ffvec req;	// Request headers + first chunk of request body (there can be several pipelined requests)
		ffvec body;	// Current request body chunk
		nml_timer timer;
		uint64 transferred;
		uint chain_pos;
	} recv;

	struct {
		range16 full, line, method, url, path, querystr, host, if_modified_since, accept_encoding,
			user_agent;
		ffstr unescaped_path;
	} req;

	void *proxy;

	struct {
		const struct nml_http_virtdoc *vdoc;
	} vspace;

	struct {
		ffvec buf; // HTML document
	} autoindex;

	struct {
		fffd f;
		ffvec buf; // File data chunk
		fffileinfo info;
		uint state;
	} file;

	struct {
		z_ctx*	zx;
		ffvec	buf; // gzip output data
		ffstr	qdata; // queued input data
	} gzip;

	ffstr acclog_buf;

	struct {
		uint64	cont_len;
		char	buf[18];
	} transfer;

	struct {
		uint code;
		uint64 content_length;
		ffstr msg, location, content_type;
		ffstr last_modified;
		ffstr headers;
		ffvec buf; // Response headers
	} resp;

	struct {
		ffiovec iov[4];
		uint iov_n;
		uint chain_pos;
		nml_timer timer;
		uint64 transferred;
	} send;

	struct {
		ffstr recv_buffer;
		uint data_sent;
		ffstr out_data;
		ffvec send_buf;
	} ssl;

	uint chain_going_back :1;
	uint chain_reset :1;

	uint ssl_handshake_logged :1;
	uint req_method_head :1;
	uint req_complete :1;
	uint req_no_chunked :1;
	uint recv_fin :1; // Received FIN from client

	uint gzip_hdr :1;
	uint gzip_finish :1;
	uint transfer_finish :1;
	uint resp_connection_keepalive :1;
	uint resp_hdr_server_disable :1; // response: don't include Server header (e.g. for proxy response)
	uint resp_transfer_encoding_chunked :1;
	uint resp_err :1;
	uint resp_done :1;
};

#define HS_REQUEST_DATA(c, range) \
	range16_tostr(&range, c->recv.req.ptr)

/** Set timer */
#define hs_timer(c, tmr, interval_sec, f, p) \
	c->conf->core.timer(c->conf->boss, tmr, interval_sec*1000, (void(*)(void*))f, p)

/** Disable timer */
#define hs_timer_stop(c, tmr) \
	c->conf->core.timer(c->conf->boss, tmr, 0, NULL, NULL)

/** Set success HTTP response status */
static inline void hs_response(nml_http_sv_conn *c, enum HTTP_STATUS status)
{
	c->resp.code = http_status_code[status];
	ffstr_setz(&c->resp.msg, http_status_msg[status]);
}

/** Set error HTTP response status */
static inline void hs_response_err(nml_http_sv_conn *c, enum HTTP_STATUS status)
{
	c->resp.code = http_status_code[status];
	if (c->resp.code == 400)
		c->resp_connection_keepalive = 0;
	ffstr_setz(&c->resp.msg, http_status_msg[status]);
	c->resp_err = 1;
}

#define HS_KEV_R(c)  &c->kev->rtask
#define HS_KEV_W(c)  &c->kev->wtask
#define HS_KCQ_CTX(c)  &c->kev->kcall
#define HS_KCQ_ACTIVE(c)  (c->kev->kcall.op != 0)

static inline int hs_async(nml_http_sv_conn *c)
{
	if (!c->kq_attached) {
		c->kq_attached = 1;
		if (c->conf->core.kq_attach(c->conf->boss, c->sk, c->kev, c)) {
			c->conf->cl_destroy(c);
			return -1;
		}
	}
	return 0;
}
static inline int hs_async_r(nml_http_sv_conn *c, void *handler)
{
	c->kev->rhandler = handler;
	return hs_async(c);
}
static inline int hs_async_w(nml_http_sv_conn *c, void *handler)
{
	c->kev->whandler = handler;
	return hs_async(c);
}
