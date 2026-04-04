/** netmill: HTTP Client/Server public interface */

#pragma once
#include <netmill.h>

/** HTTP Client: sw-module that calls the user's component chain for each outbound connection */

struct nml_http_client_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
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
		const nml_cache_if *cif;
		nml_cache_ctx *cache;
	} connect;

	const nml_ssl_if *slif;
	struct nml_ssl_ctx *ssl_ctx;

	uint max_redirect;
	uint debug_data_dump_len;
};

typedef struct nml_http_client nml_http_client;
struct nml_http_client_if {
	nml_http_client* (*create)();
	void (*free)(nml_http_client *c);
	int (*conf)(nml_http_client *c, struct nml_http_client_conf *conf);
	void (*run)(nml_http_client *c);
};

#ifdef NML_STATIC_LINKING
FF_EXTERN nml_http_client* nml_http_client_create();
FF_EXTERN void nml_http_client_free(nml_http_client *c);
FF_EXTERN int nml_http_client_conf(nml_http_client *c, struct nml_http_client_conf *conf);
FF_EXTERN void nml_http_client_run(nml_http_client *c);
#endif

struct nml_http_cl_component {
	int		(*open)(nml_http_client *c);
	void	(*close)(nml_http_client *c);
	int		(*process)(nml_http_client *c);
	char	name[16];
};


/** HTTP Client: Connection Cache */

#ifdef NML_STATIC_LINKING
FF_EXTERN void nml_http_cl_conn_cache_destroy(void *opaque, ffstr name, ffstr data);
#endif


/** HTTP Server: high-level module with a flexible setup:
* runs Worker
* listens on TCP port
* calls the user's component chain for each inbound connection */

typedef struct nml_http_sv_conn nml_http_sv_conn;
struct nml_http_server_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
	char *log_date_buffer; // passed to `nml_wrk_conf`

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
		const nml_worker_if *wif;
		const nml_tcp_listener_if *lsif;
		const struct nml_address *listen_addresses;
		uint	max_connections;
		uint	events_num;
		uint	fdlimit_timeout_sec;
		uint	timer_interval_msec;
		uint	_conn_id_counter_default;
		uint*	conn_id_counter;
		uint	listen_backlog;
		u_char	polling_mode;
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
		ffstr	www;
		ffstr	index_filename;
		uint	file_buf_size;

		ffmap	content_types_map;
		char*	content_types_data;
	} fs;

	struct {
		uint	buf_size;
		ffstr	server_name;
	} response;

	struct {
		u_char	tcp_nodelay;
		uint	timeout_sec;
	} send;

	struct {
		ffmap map;
	} virtspace;

	fffd access_log_fd;

	const nml_ssl_if *slif;
	struct nml_ssl_ctx *ssl_ctx;

	const nml_http_client_if *hcif;
	const nml_cache_if *cif;
	nml_cache_ctx *connection_cache;

	uint debug_data_dump_len;
};

typedef struct nml_http_server nml_http_server;
typedef struct nml_http_server_if nml_http_server_if;
struct nml_http_server_if {
	nml_http_server* (*create)();
	void (*free)(nml_http_server *srv);

	/** Set server configuration
	srv==NULL: initialize `conf` with default settings */
	int (*conf)(nml_http_server *srv, struct nml_http_server_conf *conf);

	/** Run server event loop */
	int (*run)(nml_http_server *srv);

	/** Send stop-signal to the worker thread */
	void (*stop)(nml_http_server *srv);
};

struct nml_http_sv_component {
	int		(*open)(nml_http_sv_conn *c);
	void	(*close)(nml_http_sv_conn *c);
	int		(*process)(nml_http_sv_conn *c);
	char	name[16];
};

#ifdef NML_STATIC_LINKING
FF_EXTERN nml_http_server* nml_http_server_create();
FF_EXTERN void nml_http_server_free(nml_http_server *s);
FF_EXTERN int nml_http_server_conf(nml_http_server *s, struct nml_http_server_conf *conf);
FF_EXTERN int nml_http_server_run(nml_http_server *s);
FF_EXTERN void nml_http_server_stop(nml_http_server *s);
FF_EXTERN const nml_http_sv_component
	nml_http_sv_proxy;
#endif


/** HTTP Server: static file component's configuration */

#ifdef NML_STATIC_LINKING
/** Initialize content-type map.
content_types: buffer on heap (e.g. "text/html htm html\r\n"); user must not use it afterwards */
FF_EXTERN void nml_http_file_init(struct nml_http_server_conf *conf, ffstr content_types);

FF_EXTERN void nml_http_file_uninit(struct nml_http_server_conf *conf);
#endif


/** HTTP Server: virtual-space component's configuration */

struct nml_http_virtdoc {
	const char *path, *method;

	/** Called by virtspace component to handle the requested document.
	The handler must set resp.content_length, response status, 'resp_done' flag.
	If resp.content_length is not set, empty '200 OK' response is returned. */
	void (*handler)(nml_http_sv_conn *c);
};

#ifdef NML_STATIC_LINKING
/** Prepare the table of virtual documents.
docs: static array (must be valid while the module is in use) */
FF_EXTERN int nml_http_virtspace_init(struct nml_http_server_conf *conf, const struct nml_http_virtdoc *docs);

FF_EXTERN void nml_http_virtspace_uninit(struct nml_http_server_conf *conf);
#endif
