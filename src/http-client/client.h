/** netmill: http-client: outbound client
2023, Simon Zolin */

#pragma once
#include <netmill.h>
#include <util/kq.h>
#include <util/range.h>
#include <util/http1.h>
#include <util/conveyor-static.h>

/** Client-context logger */

#define cl_syserrlog(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSERR, "http-cl", c->id, __VA_ARGS__)

#define cl_errlog(c, ...) \
	c->log(c->log_obj, NML_LOG_ERR, "http-cl", c->id, __VA_ARGS__)

#define cl_syswarnlog(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSWARN, "http-cl", c->id, __VA_ARGS__)

#define cl_warnlog(c, ...) \
	c->log(c->log_obj, NML_LOG_WARN, "http-cl", c->id, __VA_ARGS__)

#define cl_verblog(c, ...) \
do { \
	if (c->log_level >= NML_LOG_VERBOSE) \
		c->log(c->log_obj, NML_LOG_VERBOSE, "http-cl", c->id, __VA_ARGS__); \
} while (0)

#define cl_dbglog(c, ...) \
do { \
	if (c->log_level >= NML_LOG_DEBUG) \
		c->log(c->log_obj, NML_LOG_DEBUG, "http-cl", c->id, __VA_ARGS__); \
} while (0)

#define cl_extralog(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef cl_extralog
	#define cl_extralog(c, ...) \
	do { \
		if (c->log_level >= NML_LOG_DEBUG) \
			c->log(c->log_obj, NML_LOG_EXTRA, "http-cl", c->id, __VA_ARGS__); \
	} while (0)
#endif


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

	/** The current data passed between filters */
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
		ffuint64 transferred_r, transferred_w;
		uint filter_index;
	} io;

	struct {
		ffvec buf;
	} request;

	struct {
		ffiovec iov[3];
		uint iov_n;
		nml_timer timer;
		ffuint64 transferred;
		uint filter_index;
	} send;

	struct {
		ffvec buf, body;
		ffuint64 transferred;
		nml_timer timer;
		uint filter_index;
	} recv;

	struct {
		ffuint64 content_length;
		ffuint code;
		range16 whole, status, msg, headers, content_type, location;
		char *base;
	} response;

	struct {
		ffstr data;
		struct httpchunked chunked;
		ffuint64 size; // data left to process
	} transfer;

	struct {
		void *conn; // ffssl_conn
		ffstr recv_buffer;
		uint data_sent;
		ffstr out_data;
	} ssl;
};

#define cl_kev_r_async(c, func)  c->kev->rhandler = (void*)func
#define cl_kev_w_async(c, func)  c->kev->whandler = (void*)func
#define cl_kev_r(c)  &c->kev->rtask
#define cl_kev_w(c)  &c->kev->wtask

#define cl_kcq(c)  &c->kev->kcall
#define cl_kcq_active(c)  (c->kev->kcall.op != 0)

/** Set timer */
#define cl_timer(c, tmr, interval_msec, f, p) \
	c->conf->core.timer(c->conf->boss, tmr, interval_msec, (void(*)(void*))f, p)

/** Disable timer */
#define cl_timer_stop(c, tmr) \
	c->conf->core.timer(c->conf->boss, tmr, 0, NULL, NULL)
