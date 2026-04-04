/** netmill: SOCKS Server: HTTP connection data
2023, Simon Zolin */

#pragma once
#include <netmill-socks.h>
#include <util/kq.h>
#include <util/socks5.h>
#include <util/conveyor-static.h>
#include <ffsys/timerqueue.h>
#include <ffbase/time.h>
#include <ffbase/vector.h>

/** Client-context logger */

#define SKSV_ERR(c, ...) \
	c->log(c->log_obj, NML_LOG_ERR, "socks-sv", c->id, __VA_ARGS__)

#define SKSV_SYSWARN(c, ...) \
	c->log(c->log_obj, NML_LOG_SYSWARN, "socks-sv", c->id, __VA_ARGS__)

#define SKSV_WARN(c, ...) \
	c->log(c->log_obj, NML_LOG_WARN, "socks-sv", c->id, __VA_ARGS__)

#define SKSV_VERBOSE(c, ...) \
do { \
	if (c->log_level >= NML_LOG_VERBOSE) \
		c->log(c->log_obj, NML_LOG_VERBOSE, "socks-sv", c->id, __VA_ARGS__); \
} while (0)

#define SKSV_DEBUG(c, ...) \
do { \
	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) \
		c->log(c->log_obj, NML_LOG_DEBUG, "socks-sv", c->id, __VA_ARGS__); \
} while (0)

#define SKSV_EXTRALOG(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef SKSV_EXTRALOG
	#define SKSV_EXTRALOG(c, ...) \
	do { \
		if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) \
			c->log(c->log_obj, NML_LOG_EXTRA, "socks-sv", c->id, __VA_ARGS__); \
	} while (0)
#endif

/** Inbound client (connection) context */
struct nml_socks_sv_conn {
	struct nml_socks_server_conf *conf;

	uint log_level;
	char id[12]; // "*ID"
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *fmt, ...);
	void *log_obj;

	struct zzkevent *kev;
	ffsock sk;
	u_char peer_ip[16];
	ffushort peer_port;
	uint send_init :1;
	uint kq_attached :1;

	struct nml_conveyor conveyor;

	/** The current data passed between components */
	ffstr input, output;

	uint64 start_time_msec;

	struct {
		ffvec buf;
		nml_timer timer;
		uint64 transferred;
		uint chain_pos;
	} recv;

	struct {
		char *hostname;
		ffvec addrs;
	} resolve;

	struct {
		ffsockaddr saddr;
		nml_timer timer;
		uint i_addr;
		uint port;
	} connect;

	ffstr acclog_buf;

	struct {
		uint code;
		ffvec buf;
	} resp;

	struct {
		ffsock sk;
		struct zzkevent *kev;
		uint filter_index;
		ffstr data;
	} io;

	struct {
		ffstr data;
		uint chain_pos;
		nml_timer timer;
		uint64 transferred;
	} send;

	uint chain_going_back :1;

	uint auth_err :1;
	uint req_complete :1;
	uint recv_fin :1; // Received FIN from client
	uint resp_err :1;
	uint resp_done :1;
	uint timeout :1;
	uint r_pending :1;
	uint w_pending :1;
	uint upstream_fin :1;
	uint io_connect_result_passed :1;
};

/** Set timer */
#define sksv_timer(c, tmr, interval_sec, f, p) \
	c->conf->core.timer(c->conf->boss, tmr, interval_sec*1000, (void(*)(void*))f, p)

/** Disable timer */
#define sksv_timer_stop(c, tmr) \
	c->conf->core.timer(c->conf->boss, tmr, 0, NULL, NULL)

static inline void sksv_response_err(nml_socks_sv_conn *c, uint status)
{
	c->resp.code = status;
	c->resp_err = 1;
}

#define SKSV_KEV_R(c)  &c->kev->rtask
#define SKSV_KEV_W(c)  &c->kev->wtask
#define SKSV_KCQ_CTX(c)  &c->kev->kcall
#define SKSV_KCQ_ACTIVE(c)  (c->kev->kcall.op != 0)

static inline int sksv_async(nml_socks_sv_conn *c)
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
static inline int sksv_async_r(nml_socks_sv_conn *c, void *handler)
{
	c->kev->rhandler = handler;
	return sksv_async(c);
}
static inline int sksv_async_w(nml_socks_sv_conn *c, void *handler)
{
	c->kev->whandler = handler;
	return sksv_async(c);
}

#define SKSV_UP_KEV_R(c)  &c->io.kev->rtask
#define SKSV_UP_KEV_W(c)  &c->io.kev->wtask

#define SKSV_UP_ASYNC_R(c, handler) \
	(c)->io.kev->rhandler = (void*)handler
#define SKSV_UP_ASYNC_W(c, handler) \
	(c)->io.kev->whandler = (void*)handler
