/** netmill: public interface */

#pragma once
#include <ffsys/socket.h>
#include <ffsys/timerqueue.h>
#include <ffsys/semaphore.h>
#include <ffsys/queue.h>
#include <ffsys/filemon.h>
#include <util/taskqueue.h>
#include <util/ipaddr.h>
#include <ffbase/time.h>
#include <ffbase/vector.h>
#include <ffbase/map.h>

#define NML_VERSION  "0.9"

typedef unsigned char u_char;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long long uint64;

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

#include <util/kq.h>

enum NMLF_R {
	/** Go forward with filter's last output data chunk.
	This filter won't be called anymore. */
	NMLF_DONE,

	/** Go forward with the output data chunk */
	NMLF_FWD,

	/** Go back and return with more input data */
	NMLF_BACK,

	NMLF_ASYNC,

	NMLF_ERR,

	/** Finish the chain processing */
	NMLF_FIN,

	/** Reset control data for the chain (start anew) */
	NMLF_RESET,

	NMLF_OPEN,
	NMLF_SKIP,
};

/** A plugin implements this interface so it can act as a filter in data processing chain */
typedef struct nml_component nml_component;
typedef struct nml_http_sv_component nml_http_sv_component;
typedef struct nml_http_cl_component nml_http_cl_component;
typedef struct nml_dns_component nml_dns_component;
struct nml_component {
	/**
	Return enum NMLF_R */
	int (*open)(void *c);

	void (*close)(void *c);

	/**
	Return enum NMLF_R */
	int (*process)(void *c);

	char name[16];
};

struct ffringqueue;
struct zzkevent;
typedef struct zzkevent nml_kevent;
typedef fftask_handler nml_func;
typedef fftimerqueue_node nml_timer;
typedef fftask nml_task;
#define nml_task_set(t, func, param)  fftask_set(t, func, param)

/** Core interface, usually implemented by the root object */
typedef struct nml_core nml_core;
struct nml_core {
	struct zzkevent* (*kev_new)(void *boss);
	void (*kev_free)(void *boss, struct zzkevent *kev);

	/** Connect fd and zzkevent object */
	int (*kq_attach)(void *boss, ffsock sk, struct zzkevent *kev, void *obj);

	ffkq (*kq)(void *boss);

	void (*timer)(void *boss, nml_timer *tmr, int interval_msec, nml_func func, void *param);
	void (*task)(void *boss, nml_task *t, uint flags);
	fftime (*date)(void *boss, ffstr *dts);
};

struct nml_address {
	ffbyte ip[16];
	uint port;
};


/** Worker: default 'nml_core' implementation */

struct nml_wrk_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
	const char *log_ctx;
	char *log_date_buffer;

	/** KCQ SQ and semaphore for offloading kernel operations.
	NULL: don't use KCQ */
	struct ffringqueue *kcq_sq;
	ffsem kcq_sq_sem;

	uint timer_interval_msec;
	uint events_num;
	uint max_connections;
};

typedef struct nml_wrk nml_wrk;

FF_EXTERN const nml_core nml_wrk_core_if;
FF_EXTERN nml_wrk* nml_wrk_new();
FF_EXTERN void nml_wrk_free(nml_wrk *w);
FF_EXTERN int nml_wrk_conf(nml_wrk *w, struct nml_wrk_conf *conf);
FF_EXTERN int nml_wrk_run(nml_wrk *w);
FF_EXTERN void nml_wrk_stop(nml_wrk *w);


/** TCP & UDP Listener: sw-module which calls the parent when a new inbound connection is established */

struct nml_tcp_listener_conf {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	struct nml_core core;
	void (*on_accept)(void *boss, ffsock sk, ffsockaddr *addr);
	void *boss;

	struct nml_address addr;
	uint fdlimit_timeout_sec;
	uint backlog;
	uint reuse_port :1;
	uint v6_only :1;
};

typedef struct nml_tcp_listener nml_tcp_listener;
FF_EXTERN nml_tcp_listener* nml_tcp_listener_new();
FF_EXTERN void nml_tcp_listener_free(nml_tcp_listener *l);
FF_EXTERN int nml_tcp_listener_conf(nml_tcp_listener *l, struct nml_tcp_listener_conf *conf);
FF_EXTERN int nml_tcp_listener_run(nml_tcp_listener *l);

struct nml_udp_listener_conf {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	struct nml_core core;
	void (*on_recv_udp)(void *boss, ffsock sk, ffsockaddr *addr, ffstr request);
	void *boss;

	struct nml_address addr;
	uint reuse_port :1;
	uint v6_only :1;
};

typedef struct nml_udp_listener nml_udp_listener;
FF_EXTERN nml_udp_listener* nml_udp_listener_new();
FF_EXTERN void nml_udp_listener_free(nml_udp_listener *l);
FF_EXTERN int nml_udp_listener_conf(nml_udp_listener *l, struct nml_udp_listener_conf *conf);
FF_EXTERN int nml_udp_listener_run(nml_udp_listener *l);


/* SSL configuration */

struct ffssl_ctx_conf;
struct nml_ssl_ctx {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	struct ffssl_ctx_conf *ctx_conf;
	void *ctx; // ffssl_ctx*
};

FF_EXTERN int nml_ssl_init(struct nml_ssl_ctx *ctx);
FF_EXTERN void nml_ssl_uninit(struct nml_ssl_ctx *ctx);

FF_EXTERN const nml_http_cl_component
	nml_http_cl_ssl_handshake,
	nml_http_cl_ssl_recv,
	nml_http_cl_ssl_send,
	nml_http_cl_ssl_req,
	nml_http_cl_ssl_resp;


/** HTTP Server: high-level module with a flexible setup:
 calls the user's filter chain for each inbound connection;
 maintains the necessary infrastructure (KQ, TCP listener, timer queue, task queue)
 and implements Core interface */

typedef struct nml_http_sv_conn nml_http_sv_conn;
struct nml_http_server_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
	char *log_date_buffer;

	struct nml_core core;
	void (*on_accept)(void *boss, ffsock csock, ffsockaddr *peer);
	void (*on_complete)(void *boss, ffsock sk, struct zzkevent *kev);
	void *boss;

	/** KCQ SQ and semaphore for offloading kernel operations.
	NULL: don't use KCQ */
	struct ffringqueue *kcq_sq;
	ffsem kcq_sq_sem;

	void (*cl_wake)(nml_http_sv_conn *c);
	void (*cl_destroy)(nml_http_sv_conn *c);

	struct {
		const struct nml_address *listen_addresses;
		uint	max_connections;
		uint	events_num;
		uint	fdlimit_timeout_sec;
		uint	timer_interval_msec;
		uint	_conn_id_counter_default;
		uint*	conn_id_counter;
		uint	listen_backlog;
		ffbyte	polling_mode;
		uint	reuse_port :1;
		uint	v6_only :1;
	} server;

	const nml_http_sv_component **chain;

	uint max_keep_alive_reqs;

	struct {
		uint buf_size;
		uint timeout_sec;
	} receive;
	struct {
		uint buf_size;
		uint timeout_sec;
	} recv_body;

	struct {
		ffstr www;
		ffstr index_filename;
		uint file_buf_size;

		ffmap content_types_map;
		char *content_types_data;
	} fs;

	struct {
		uint buf_size;
		ffstr server_name;
	} response;

	struct {
		ffbyte tcp_nodelay;
		uint timeout_sec;
	} send;

	struct {
		ffmap map;
	} virtspace;

	uint debug_data_dump_len;
};

typedef struct nml_http_server nml_http_server;
FF_EXTERN nml_http_server* nml_http_server_new();
FF_EXTERN void nml_http_server_free(nml_http_server *srv);

/** Set server configuration
srv==NULL: initialize `conf` with default settings */
FF_EXTERN int nml_http_server_conf(nml_http_server *srv, struct nml_http_server_conf *conf);

/** Run server event loop */
FF_EXTERN int nml_http_server_run(nml_http_server *srv);

/** Send stop-signal to the worker thread */
FF_EXTERN void nml_http_server_stop(nml_http_server *srv);

struct nml_http_sv_component {
	int		(*open)(nml_http_sv_conn *c);
	void	(*close)(nml_http_sv_conn *c);
	int		(*process)(nml_http_sv_conn *c);
	char	name[16];
};

FF_EXTERN const nml_http_sv_component
	nml_http_sv_proxy;


/** HTTP Server: file filter configuration */

/** Initialize content-type map.
content_types: buffer on heap (e.g. "text/html htm html\r\n"); user must not use it afterwards */
FF_EXTERN void nml_http_file_init(struct nml_http_server_conf *conf, ffstr content_types);

FF_EXTERN void nml_http_file_uninit(struct nml_http_server_conf *conf);


/** HTTP Server: virtual-space filter configuration */

struct nml_http_virtdoc {
	const char *path, *method;

	/** Called by virtspace filter to handle the requested document.
	The handler must set resp.content_length, response status, 'resp_done' flag.
	If resp.content_length is not set, empty '200 OK' response is returned. */
	void (*handler)(nml_http_sv_conn *c);
};

/** Prepare the table of virtual documents.
docs: static array (must be valid while the module is in use) */
FF_EXTERN int nml_http_virtspace_init(struct nml_http_server_conf *conf, const struct nml_http_virtdoc *docs);

FF_EXTERN void nml_http_virtspace_uninit(struct nml_http_server_conf *conf);


/** Cache */

typedef struct nml_cache_ctx nml_cache_ctx;

/** Create context */
FF_EXTERN nml_cache_ctx* nml_cache_create();

FF_EXTERN void nml_cache_destroy(nml_cache_ctx *cx);

typedef void (*nml_cache_destroy_t)(void *opaque, ffstr name, ffstr data);
struct nml_cache_conf {
	uint	log_level; // enum NML_LOG
	void	*log_obj;
	void	(*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);

	uint	max_items;
	uint	ttl_sec;

	nml_cache_destroy_t destroy;
	void *opaque;
};

/** Apply configuration */
FF_EXTERN int nml_cache_conf(nml_cache_ctx *cx, struct nml_cache_conf *conf);

/** Reserve data space inside a newly created cache entry.
User must call nml_cache_add() or nml_cache_free(). */
FF_EXTERN ffstr nml_cache_reserve(nml_cache_ctx *cx, size_t data_len);

/** Free cache entry.
nml_cache_conf.destroy() will be called. */
FF_EXTERN void nml_cache_free(nml_cache_ctx *cx, ffstr data);

/** Add data to cache. */
FF_EXTERN int nml_cache_add(nml_cache_ctx *cx, ffstr name, ffstr data);

/** Fetch and remove data from cache index.
User must call nml_cache_free(). */
FF_EXTERN ffstr nml_cache_fetch(nml_cache_ctx *cx, ffstr name);


/** HTTP Client: sw-module that calls the user's filter chain for each outbound connection */

struct nml_http_client_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void *log_obj;
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	char id[12];

	void *wake_param;
	void (*wake)(void *param);

	struct nml_core core;
	void *boss;

	ffstr method,
		host, // "hostname[:port]"
		path,
		headers;
	const nml_http_cl_component **chain;

	ffstr proxy_host;
	union {
		uint proxy_port;
		uint server_port; // override port value from 'host'
	};

	uint connect_timeout_msec, send_timeout_msec;
	struct {
		uint hdr_buf_size, max_buf, body_buf_size;
		uint timeout_msec;
	} receive;

	struct {
		nml_cache_ctx *cache;
	} connect;

	struct nml_ssl_ctx *ssl_ctx;

	uint max_redirect;
	uint debug_data_dump_len;
};

typedef struct nml_http_client nml_http_client;

FF_EXTERN nml_http_client* nml_http_client_new();
FF_EXTERN void nml_http_client_free(nml_http_client *c);

FF_EXTERN int nml_http_client_conf(nml_http_client *c, struct nml_http_client_conf *conf);

FF_EXTERN void nml_http_client_run(nml_http_client *c);

struct nml_http_cl_component {
	int		(*open)(nml_http_client *c);
	void	(*close)(nml_http_client *c);
	int		(*process)(nml_http_client *c);
	char	name[16];
};

FF_EXTERN const nml_http_cl_component
	nml_http_cl_resolve,
	nml_http_cl_connection_cache,
	nml_http_cl_connect,
	nml_http_cl_io,
	nml_http_cl_send,
	nml_http_cl_recv,
	nml_http_cl_response,
	nml_http_cl_request,
	nml_http_cl_transfer,
	nml_http_cl_redir;


/** DNS Server */

enum NML_DNS_BLOCK {
	NML_DNS_BLOCK_EMPTY,
	NML_DNS_BLOCK_NULL_IP,
	NML_DNS_BLOCK_LOCAL_IP,
	NML_DNS_BLOCK_NXDOMAIN,
	NML_DNS_BLOCK_REFUSED,
	NML_DNS_BLOCK_DROP,
};

typedef struct nml_dns_sv_conn nml_dns_sv_conn;
struct nml_dns_server_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
	char *log_date_buffer;

	struct nml_core core;
	void *boss;

	void (*wake)(nml_dns_sv_conn *c);

	struct {
		const struct nml_address *listen_addresses; // server UDP socket listen address (default: <any>:53)
		uint	max_connections;
		uint	events_num;
		uint	timer_interval_msec;
		uint	_conn_id_counter_default;
		uint*	conn_id_counter;
		ffbyte	polling_mode;
		uint	reuse_port :1;
		uint	v6_only :1;
	} server;

	const nml_dns_component **chain; // conveyor components for inbound DNS request processing (required)

	struct {
		ffvec	filenames; // char*[]
		uint	file_refresh_period_sec;
		uint	rewrite_ttl;
		uint	block_ttl;
		uint	block_mode; // enum NML_DNS_BLOCK
		uint	block_aaaa :1; // block AAAA requests
		uint	monitor_change :1; // monitor for file change

		ffvec	sources; // struct source[]
		ffmap	index; // host -> struct entry*
		uint64	hits, misses; // stats

		nml_timer refresh_timer;
#ifdef FF_LINUX
		fffilemon fm;
		struct zzkevent fm_kev;
		char	fm_buf[16*1024];
#endif
	} hosts;

	struct {
		const char *dir;
		uint	min_ttl;
		uint	error_ttl;
	} filecache;

	struct {
		ffvec	upstreams; // char*[]
		uint	read_timeout_msec;
		uint	resend_attempts;

		ffvec	servers; // struct upstream[]
		uint	iserver;
		uint64	out_reqs, in_msgs, in_data, out_data; // stats

		struct nml_ssl_ctx *doh_ssl_ctx; // DoH client SSL context (required)
		nml_cache_ctx *doh_connection_cache; // DoH client connection cache
	} upstreams;

	uint debug_data_dump_len;
};

typedef struct nml_dns_server nml_dns_server;
FF_EXTERN nml_dns_server* nml_dns_server_new();
FF_EXTERN void nml_dns_server_free(nml_dns_server *srv);

/** Set server configuration
srv==NULL: initialize `conf` with default settings */
FF_EXTERN int nml_dns_server_conf(nml_dns_server *srv, struct nml_dns_server_conf *conf);

/** Run server event loop */
FF_EXTERN int nml_dns_server_run(nml_dns_server *srv);

/** Send stop-signal to the worker thread */
FF_EXTERN void nml_dns_server_stop(nml_dns_server *srv);

struct nml_dns_component {
	int		(*open)(nml_dns_sv_conn *c);
	void	(*close)(nml_dns_sv_conn *c);
	int		(*process)(nml_dns_sv_conn *c);
	char	name[16];
};


/** DNS Server: hosts */

/** Initialize hosts file.
conf.hosts.filenames is an array of file names containing host rules. Syntax:
  # comment
  ! also a comment
  block.com         # block 'block.com' and '*.block.com'
  ||block.com^      # block 'block.com' and '*.block.com'
  +un.block.com     # unblock 'un.block.com'
  1.2.3.4 host.com  # respond with '1.2.3.4' for 'host.com'
*/
FF_EXTERN void nml_dns_hosts_init(struct nml_dns_server_conf *conf);

FF_EXTERN void nml_dns_hosts_uninit(struct nml_dns_server_conf *conf);

FF_EXTERN int nml_dns_hosts_find(struct nml_dns_server_conf *conf, ffstr name, ffip6 *ip);

/** Re-read source files if necessary */
FF_EXTERN void nml_dns_hosts_refresh(struct nml_dns_server_conf *conf);


/** DNS Server: upstreams */

/** Initialize upstream servers.
conf.upstreams.upstreams is an array of DNS server addresses */
FF_EXTERN int nml_dns_upstreams_init(struct nml_dns_server_conf *conf);

FF_EXTERN void nml_dns_upstreams_uninit(struct nml_dns_server_conf *conf);


/** DNS Server: UDP upsteam server */

FF_EXTERN void* nml_dns_udp_create(struct nml_dns_server_conf *conf, const char *addr);

FF_EXTERN void nml_dns_udp_free(void *p);


/** DNS Server: DoH upsteam server */

FF_EXTERN void* nml_dns_doh_create(struct nml_dns_server_conf *conf, const char *addr);

FF_EXTERN void nml_dns_doh_free(void *p);


/** DNS Server: file-cache */

FF_EXTERN int nml_dns_filecache_init(struct nml_dns_server_conf *conf);


/** Get information about system network interfaces */

struct nml_nif {
	char name[16];
	char ip[16];
};

struct nml_nif_info {
	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;

	ffslice nifs; // struct nml_nif[]
};

static inline void nml_nif_info_destroy(struct nml_nif_info *i) {
	ffslice_free(&i->nifs);
}

FF_EXTERN int nml_nif_info(struct nml_nif_info *info);
