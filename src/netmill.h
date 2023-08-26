/** netmill: public interface
2023, Simon Zolin */

#pragma once
#include <FFOS/socket.h>
#include <FFOS/timerqueue.h>
#include <FFOS/semaphore.h>
#include <util/taskqueue.h>
#include <ffbase/time.h>
#include <ffbase/map.h>

#define NML_VERSION  "0.6"

#ifdef FF_WIN
typedef unsigned int uint;
#endif

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
struct nml_filter {
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
typedef fftimerqueue_node nml_timer;
typedef fftask nml_task;
#define nml_task_set(t, func, param)  fftask_set(t, func, param)
typedef struct nml_tcp_listener nml_tcp_listener;
typedef struct nml_udp_listener nml_udp_listener;
typedef struct nml_http_server nml_http_server;
typedef struct nml_http_sv_conn nml_http_sv_conn;

/** Core interface, usually implemented by the root object */
struct nml_core {
	struct zzkevent* (*kev_new)(void *boss);
	void (*kev_free)(void *boss, struct zzkevent *kev);
	int (*kq_attach)(void *boss, ffsock sk, struct zzkevent *kev, void *obj);
	void (*timer)(void *boss, nml_timer *tmr, int interval_msec, fftimerqueue_func func, void *param);
	void (*task)(void *boss, nml_task *t, uint flags);
	fftime (*date)(void *boss, ffstr *dts);
};

struct nml_address {
	ffbyte ip[16];
	uint port;
};


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

FF_EXTERN nml_udp_listener* nml_udp_listener_new();
FF_EXTERN void nml_udp_listener_free(nml_udp_listener *l);
FF_EXTERN int nml_udp_listener_conf(nml_udp_listener *l, struct nml_udp_listener_conf *conf);
FF_EXTERN int nml_udp_listener_run(nml_udp_listener *l);


/** HTTP Server: high-level module with a flexible setup:
 calls the user's filter chain for each inbound connection;
 maintains the necessary infrastructure (KQ, TCP listener, timer queue, task queue)
 and implements Core interface */

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
		uint max_connections;
		uint events_num;
		uint fdlimit_timeout_sec;
		uint timer_interval_msec;
		uint _conn_id_counter_default;
		uint *conn_id_counter;
		uint listen_backlog;
		ffbyte polling_mode;
		uint reuse_port :1;
		uint v6_only :1;
	} server;

	const struct nml_filter **filters;

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

FF_EXTERN nml_http_server* nml_http_server_new();
FF_EXTERN void nml_http_server_free(nml_http_server *srv);

/** Set server configuration
srv==NULL: initialize `conf` with default settings */
FF_EXTERN int nml_http_server_conf(nml_http_server *srv, struct nml_http_server_conf *conf);

/** Run server event loop */
FF_EXTERN int nml_http_server_run(nml_http_server *srv);

/** Send stop-signal to the worker thread */
FF_EXTERN void nml_http_server_stop(nml_http_server *srv);


/** HTTP Server: file filter configuration */

/** file: initialize content-type map
content_types: heap buffer (e.g. "text/html	htm html\r\n"); user must not use it afterwards */
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

	ffstr method, host, path, headers;
	const struct nml_filter **filters;

	ffstr proxy_host;
	uint proxy_port;

	uint connect_timeout_msec, send_timeout_msec;
	struct {
		uint hdr_buf_size, max_buf, body_buf_size;
		uint timeout_msec;
	} receive;

	uint max_redirect;
	uint debug_data_dump_len;
};

typedef struct nml_http_client nml_http_client;

FF_EXTERN nml_http_client* nml_http_client_new();
FF_EXTERN void nml_http_client_free(nml_http_client *c);

FF_EXTERN int nml_http_client_conf(nml_http_client *c, struct nml_http_client_conf *conf);

FF_EXTERN void nml_http_client_run(nml_http_client *c);
