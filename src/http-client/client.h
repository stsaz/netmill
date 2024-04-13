/** netmill: http-client: connection data
2023, Simon Zolin */

#pragma once
#include <netmill.h>
#include <util/kq.h>
#include <util/range.h>
#include <util/http1.h>
#include <util/conveyor-static.h>

/** Client-context logger */

#define HC_SYSERR(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSERR, "http-cl", c->id, __VA_ARGS__)

#define HC_ERR(c, ...) \
	c->log(c->log_obj, NML_LOG_ERR, "http-cl", c->id, __VA_ARGS__)

#define HC_SYSWARN(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSWARN, "http-cl", c->id, __VA_ARGS__)

#define HC_WARN(c, ...) \
	c->log(c->log_obj, NML_LOG_WARN, "http-cl", c->id, __VA_ARGS__)

#define HC_VERBOSE(c, ...) \
do { \
	if (c->log_level >= NML_LOG_VERBOSE) \
		c->log(c->log_obj, NML_LOG_VERBOSE, "http-cl", c->id, __VA_ARGS__); \
} while (0)

#define HC_DEBUG(c, ...) \
do { \
	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) \
		c->log(c->log_obj, NML_LOG_DEBUG, "http-cl", c->id, __VA_ARGS__); \
} while (0)

#define HC_EXTRALOG(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef HC_EXTRALOG
	#define HC_EXTRALOG(c, ...) \
	do { \
		if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) \
			c->log(c->log_obj, NML_LOG_EXTRA, "http-cl", c->id, __VA_ARGS__); \
	} while (0)
#endif

typedef struct z_ctx z_ctx;
struct nml_http_client {
	struct nml_http_client_conf *conf;

	void *log_obj;
	uint log_level;
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *fmt, ...);
	char id[12];
	void (*wake)(nml_http_client *c);

	struct zzkevent *kev;

	char *redirect_location;
	uint redirect_n;

	struct nml_conveyor conveyor;

	// The following region is cleared on 30x redirect

	/** The current data passed between components */
	ffstr input, output;

	ffsock sk;
	uint chain_reset :1;
	uint chain_going_back :1;
	uint name_resolved :1;
	uint timeout :1;
	uint connection_close :1;
	uint connection_from_cache :1;
	uint recv_fin :1;
	uint req_complete :1;
	uint response_chunked :1;
	uint resp_complete :1;
	uint r_pending :1;
	uint w_pending :1;
	uint io_connect_result_passed :1;
	uint ssl_handshake_logged :1;

	struct {
		char *hostname;
		uint port;
		ffvec addrs;
	} resolve;

	struct {
		ffsockaddr saddr;
		nml_timer timer;
		uint i_addr;
		u_char cache_name[16+2];
		ffstr cache_data;
	} connect;

	struct {
		ffiovec iov[1];
		uint iov_n;
		ffvec buf;
		uint64 transferred_r, transferred_w;
		uint filter_index;
	} io;

	struct {
		ffvec buf;
	} request;

	struct {
		ffiovec iov[3];
		uint iov_n;
		nml_timer timer;
		uint64 transferred;
		uint filter_index;
	} send;

	struct {
		ffvec buf, body;
		uint64 transferred;
		nml_timer timer;
		uint filter_index;
	} recv;

	struct {
		uint64 content_length;
		uint code;
		range16 whole, status, msg, headers, content_type, content_encoding, location;
		char *base;
	} response;

	struct {
		ffstr data;
		struct httpchunked chunked;
		uint64 size; // data left to process
	} transfer;

	struct {
		void *conn; // ffssl_conn
		ffstr recv_buffer;
		uint data_sent;
		ffstr out_data;
	} ssl;

	struct {
		z_ctx*	zx;
		ffvec	buf;
		ffstr	qdata; // queued input data
	} gzip;
};

#define HC_RESPONSE_DATA(c, range) \
	range16_tostr(&range, c->recv.buf.ptr)

#define HC_ASYNC_R(c, func)  c->kev->rhandler = (void*)func
#define HC_ASYNC_W(c, func)  c->kev->whandler = (void*)func
#define HC_KEV_R(c)  &c->kev->rtask
#define HC_KEV_W(c)  &c->kev->wtask

#define HC_KCQ_CTX(c)  &c->kev->kcall
#define HC_KCQ_ACTIVE(c)  (c->kev->kcall.op != 0)

/** Set timer */
#define hc_timer(c, tmr, interval_msec, f, p) \
	c->conf->core.timer(c->conf->boss, tmr, interval_msec, (void(*)(void*))f, p)

/** Disable timer */
#define hc_timer_stop(c, tmr) \
	c->conf->core.timer(c->conf->boss, tmr, 0, NULL, NULL)
