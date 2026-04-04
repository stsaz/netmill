/** netmill: public interface */

#pragma once
#include <ffsys/error.h>
#include <util/taskqueue.h>
#include <ffsys/socket.h>
#include <ffsys/timerqueue.h>
#include <ffsys/semaphore.h>
#include <ffsys/queue.h>
#include <ffsys/filemon.h>
#include <ffbase/time.h>
#include <ffbase/vector.h>
#include <ffbase/map.h>

#define NML_VERSION  "0.12"
#define NML_CORE_VER  11

typedef unsigned char u_char;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long long uint64;

#include <util/ipaddr.h>

#define NML_ASSERT(X)  assert(X)

enum NML_LOG {
	NML_LOG_SYSFATAL,
	NML_LOG_SYSERR,
	NML_LOG_ERR,
	NML_LOG_SYSWARN,
	NML_LOG_WARN,
	NML_LOG_INFO,
	NML_LOG_VERBOSE,
	NML_LOG_DEBUG,
	NML_LOG_EXTRA,
};

#define ZZKQ_LOG_SYSERR  NML_LOG_SYSERR
#define ZZKQ_LOG_ERR  NML_LOG_ERR
#define ZZKQ_LOG_DEBUG  NML_LOG_DEBUG
#ifdef NML_ENABLE_LOG_EXTRA
#define ZZKQ_LOG_EXTRA  NML_LOG_EXTRA
#endif

#define FFTASKQUEUE_LOG_DEBUG  NML_LOG_DEBUG
#ifdef NML_ENABLE_LOG_EXTRA
#define FFTASKQUEUE_LOG_EXTRA  NML_LOG_EXTRA
#endif

#include <util/kq.h>

enum NMLR_R {
	/** Go forward with component's last output data chunk.
	This component won't be called anymore. */
	NMLR_DONE,

	/** Go forward with the output data chunk */
	NMLR_FWD,

	/** Go back and return with more input data */
	NMLR_BACK,

	NMLR_ASYNC,

	NMLR_ERR,

	/** Finish the chain processing */
	NMLR_FIN,

	/** Reset control data for the chain (start anew) */
	NMLR_RESET,

	NMLR_OPEN,
	NMLR_SKIP,
};

/** A plugin implements this interface so it can act as a component in data processing chain */
typedef struct nml_component nml_component;
typedef struct nml_http_sv_component nml_http_sv_component;
typedef struct nml_http_cl_component nml_http_cl_component;
typedef struct nml_dns_component nml_dns_component;
struct nml_component {
	/**
	Return enum NMLR_R */
	int (*open)(void *c);

	void (*close)(void *c);

	/**
	Return enum NMLR_R */
	int (*process)(void *c);

	char name[16];
};


/** Executor interface */
typedef struct nml_exe nml_exe;
struct nml_exe {
	uint log_level; // enum NML_LOG
	char *log_date_buffer;

	/** Print log message */
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);

	void (*exit)(int exit_code);

	/** Get absolute path for files in app directory.
	Return newly allocated string, free with ffmem_free(). */
	char* (*path)(const char *name);

	/** Find operation interface in a module.  Load it on first use.
	name: "module_name.operation_name"
	*/
	const void* (*provide)(const char *name);

	void (*print)(const char *text);
};

struct ffringqueue;
struct zzkevent;
typedef struct zzkevent nml_kevent;
typedef fftask_handler nml_func;
typedef fftimerqueue_node nml_timer;
typedef fftask nml_task;
#define nml_task_set(t, func, param)  fftask_set(t, func, param)

/** Core interface */
typedef struct nml_core nml_core;
struct nml_core {
	struct zzkevent* (*kev_new)(void *o);

	void (*kev_free)(void *o, struct zzkevent *kev);

	/** Connect fd and zzkevent object */
	int (*kq_attach)(void *o, ffsock sk, struct zzkevent *kev, void *obj);

	ffkq (*kq)(void *o);

	void (*timer)(void *o, nml_timer *tmr, int interval_msec, nml_func func, void *param);

	void (*task)(void *o, nml_task *t, uint flags);

	fftime (*date)(void *o, ffstr *dts);
};

struct nml_address {
	u_char	ip[16];
	uint	port;
};


/** Worker: implements `nml_core` interface. */

typedef void (*nml_log_func)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);

struct nml_wrk_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	nml_log_func log;
	void *log_obj;
	const char *log_ctx;
	char *log_date_buffer; // the worker periodically writes new datetime (as a NULL-terminated string) here

	/** KCQ SQ and semaphore for offloading kernel operations.
	NULL: don't use KCQ */
	struct ffringqueue *kcq_sq;
	ffsem kcq_sq_sem;

	uint timer_interval_msec;
	uint events_num;
	uint max_connections;
};

typedef struct nml_wrk nml_wrk;
typedef struct nml_worker_if nml_worker_if;
struct nml_worker_if {
	nml_wrk* (*create)(nml_core *core);
	void (*free)(nml_wrk *w);
	int (*conf)(nml_wrk *w, struct nml_wrk_conf *conf);
	int (*run)(nml_wrk *w);
	void (*stop)(nml_wrk *w);
};

/* netmill module.
Usage:
- Executor gets the operation name from user command line
- Core loads the corresponding module file and imports "netmill_module" symbol.
  A module implements `nml_module` interface and exports it as "netmill_module".
- Core checks if the loaded module is compatible with Core
- Core calls `fcom_module.provide()` to get operation interface
- Core calls `fcom_module.init()`
- Executor calls `nml_operation_if.create()` and `run()` and passes the control to Operator
- Executor passes all system signals from the user to Operator while it's running
- Operator calls `nml_core.signal()` to exit
- Core calls `fcom_module.destroy()`
*/

typedef void nml_op;

/** Primary operation interface. */
typedef struct nml_operation_if nml_operation_if;
struct nml_operation_if {
	/**
	argv: NULL-terminated array of command-line parameters */
	nml_op* (*create)(char **argv);
	void (*close)(nml_op *op);
	void (*run)(nml_op *op);
	void (*signal)(nml_op *op, uint signal);
};

/** A module exports this interface as "netmill_module". */
typedef struct nml_module nml_module;
struct nml_module {
	const char version[12];
	uint ver_core;
	void (*init)(const nml_exe *x);
	void (*close)();
	const void* (*provide)(const char *name);
};

#define NML_MOD_DEFINE(name) \
	FF_EXPORT const struct nml_module netmill_module = { \
		NML_VERSION, \
		NML_CORE_VER, \
		name##_init, \
		name##_destroy, \
		name##_provide, \
	}


/** TCP & UDP Listener: call the parent when a new inbound connection is established. */

struct nml_tcp_listener_conf {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	struct nml_core core;
	void (*on_accept)(void *opaque, ffsock sk, ffsockaddr *addr);
	void *opaque;

	struct nml_address addr;
	uint fdlimit_timeout_sec;
	uint backlog;
	uint reuse_port :1;
	uint v6_only :1;
};

typedef struct nml_tcp_listener nml_tcp_listener;
typedef struct nml_tcp_listener_if nml_tcp_listener_if;
struct nml_tcp_listener_if {
	nml_tcp_listener* (*create)();
	void (*free)(nml_tcp_listener *l);
	int (*conf)(nml_tcp_listener *l, struct nml_tcp_listener_conf *conf);
	int (*run)(nml_tcp_listener *l);
};

struct nml_udp_listener_conf {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	struct nml_core core;
	void (*on_recv_udp)(void *opaque, ffsock sk, ffsockaddr *addr, ffstr request);
	void *opaque;

	struct nml_address addr;
	uint reuse_port :1;
	uint v6_only :1;
};

typedef struct nml_udp_listener nml_udp_listener;
typedef struct nml_udp_listener_if nml_udp_listener_if;
struct nml_udp_listener_if {
	nml_udp_listener* (*create)();
	void (*free)(nml_udp_listener *l);
	int (*conf)(nml_udp_listener *l, struct nml_udp_listener_conf *conf);
	int (*run)(nml_udp_listener *l);
};


/** Cache: in-memory data storage */

typedef struct nml_cache_ctx nml_cache_ctx;

typedef void (*nml_cache_destroy_t)(void *opaque, ffstr name, ffstr data);
struct nml_cache_conf {
	uint	log_level; // enum NML_LOG
	void	(*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void	*log_obj;

	uint	max_items;
	uint	ttl_sec;

	fftime (*timestamp)(void *opaque);
	nml_cache_destroy_t destroy;
	void *opaque;
};

typedef struct nml_cache_if nml_cache_if;
struct nml_cache_if {
	/** Create context. */
	nml_cache_ctx* (*create)();

	void (*destroy)(nml_cache_ctx *cx);

	/** Initialize or apply configuration. */
	int (*conf)(nml_cache_ctx *cx, struct nml_cache_conf *conf);

	/** Reserve data space inside a newly created cache entry.
	Return data region; user must call add() or free(). */
	ffstr (*reserve)(nml_cache_ctx *cx, size_t data_len);

	/** Free cache entry.
	nml_cache_conf.destroy() will be called. */
	void (*free)(nml_cache_ctx *cx, ffstr data);

	/** Add data to cache.
	name: stored internally as-is and is passed to nml_cache_conf.destroy() */
	int (*add)(nml_cache_ctx *cx, ffstr name, ffstr data);

	/** Fetch and remove data from cache index.
	User must call free(). */
	ffstr (*fetch)(nml_cache_ctx *cx, ffstr name);
};


/* SSL configuration */

struct ffssl_ctx_conf;
struct nml_ssl_ctx {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	struct ffssl_ctx_conf *ctx_conf;
	void *ctx; // ffssl_ctx*
};

typedef struct ssl_st ffssl_conn;
struct ffssl_cert_newinfo;
typedef struct nml_ssl_if nml_ssl_if;
struct nml_ssl_if {
	int (*init)(struct nml_ssl_ctx *ctx);
	void (*uninit)(struct nml_ssl_ctx *ctx);
	void (*conn_free)(ffssl_conn *c);
	int (*cert_pem_create)(const char *fn, uint pkey_bits, struct ffssl_cert_newinfo *ci);
};

#ifdef NML_STATIC_LINKING
FF_EXTERN int nml_ssl_init(struct nml_ssl_ctx *ctx);
FF_EXTERN void nml_ssl_uninit(struct nml_ssl_ctx *ctx);
#endif


typedef struct nml_http_client_if nml_http_client_if;


struct hosts {
	ffmap index; // "host" -> struct hosts_entry*
};


/** Get information about system network interfaces */

struct nml_nif_info {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	void *nc;
};

/**
nifs: struct nml_nif[] */
FF_EXTERN int nml_nif_info(struct nml_nif_info *info, ffslice *nifs);

FF_EXTERN void nml_nif_info_destroy(struct nml_nif_info *i);
