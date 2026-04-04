/** netmill: DNS Server public interface */

#pragma once
#include <netmill.h>

/** DNS Server:
* runs Worker
* listens on UDP port
* calls the user's component chain for each request */

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
	char *log_date_buffer; // passed to `nml_wrk_conf`

	struct nml_core core;
	void *boss;

	void (*wake)(nml_dns_sv_conn *c);

	struct {
		const nml_worker_if *wif;
		const nml_udp_listener_if *lsif;
		const struct nml_address *listen_addresses; // server UDP socket listen address (default: <any>:53)
		uint	max_connections;
		uint	events_num;
		uint	timer_interval_msec;
		uint	_conn_id_counter_default;
		uint*	conn_id_counter;
		u_char	polling_mode;
		uint	reuse_port :1;
		uint	v6_only :1;
	} server;

	const nml_dns_component **chain; // (Required) Conveyor components for inbound DNS request processing

	struct {
		ffvec	filenames; // char*[]
		uint	file_refresh_period_sec;
		uint	rewrite_ttl;
		uint	block_ttl;
		uint	block_mode; // enum NML_DNS_BLOCK
		uint	block_aaaa :1; // block AAAA requests
		uint	monitor_change :1; // monitor for file change

		ffvec	sources; // struct source[]
		struct hosts hosts;

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
		ffvec	addresses; // char*[]
		uint	read_timeout_msec;
		uint	resend_attempts;

		ffvec	servers; // struct upstream[]
		uint	iserver;

		const nml_http_client_if *hcif; // (Required for DoH)
		const nml_ssl_if *slif; // (Required for DoH)
		struct nml_ssl_ctx *doh_ssl_ctx; // (Required for DoH) DoH client SSL context
		const nml_cache_if *cif;
		nml_cache_ctx *doh_connection_cache; // DoH client connection cache
		const nml_http_cl_component **doh_chain; // (Required for DoH) Conveyor components for HTTP client
	} upstreams;

	uint debug_data_dump_len;

	struct {
		struct {
			uint64	hits, misses;
		} hosts;
		struct {
			uint64	out_reqs, in_msgs, in_data, out_data;
		} upstreams;
	} stat;
};

typedef struct nml_dns_server nml_dns_server;

#ifdef NML_STATIC_LINKING
FF_EXTERN nml_dns_server* nml_dns_server_create();
FF_EXTERN void nml_dns_server_free(nml_dns_server *srv);

/** Set server configuration
srv==NULL: initialize `conf` with default settings */
FF_EXTERN int nml_dns_server_conf(nml_dns_server *srv, struct nml_dns_server_conf *conf);

/** Run server event loop */
FF_EXTERN int nml_dns_server_run(nml_dns_server *srv);

/** Send stop-signal to the worker thread */
FF_EXTERN void nml_dns_server_stop(nml_dns_server *srv);
#endif

struct nml_dns_component {
	int		(*open)(nml_dns_sv_conn *c);
	void	(*close)(nml_dns_sv_conn *c);
	int		(*process)(nml_dns_sv_conn *c);
	char	name[16];
};


/** DNS Server: hosts */

#ifdef NML_STATIC_LINKING
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
#endif


/** DNS Server: upstreams */

#ifdef NML_STATIC_LINKING
/** Initialize upstream servers.
conf.upstreams.addresses is an array of DNS server addresses */
FF_EXTERN int nml_dns_upstreams_init(struct nml_dns_server_conf *conf);

FF_EXTERN void nml_dns_upstreams_uninit(struct nml_dns_server_conf *conf);
#endif


/** DNS Server: UDP upsteam server */

#ifdef NML_STATIC_LINKING
FF_EXTERN void* nml_dns_udp_create(struct nml_dns_server_conf *conf, const char *addr);

FF_EXTERN void nml_dns_udp_free(void *p);
#endif


/** DNS Server: DoH upsteam server */

#ifdef NML_STATIC_LINKING
FF_EXTERN void* nml_dns_doh_create(struct nml_dns_server_conf *conf, const char *addr);

FF_EXTERN void nml_dns_doh_free(void *p);
#endif


/** DNS Server: file-cache */

#ifdef NML_STATIC_LINKING
FF_EXTERN int nml_dns_filecache_init(struct nml_dns_server_conf *conf);
#endif
