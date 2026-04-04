/** netmill: SOCKS5 Server public interface */

#pragma once
#include <netmill.h>

typedef struct nml_socks_sv_conn nml_socks_sv_conn;
struct nml_socks_server_conf {
	void *opaque;

	uint log_level; // enum NML_LOG
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
	char *log_date_buffer; // passed to `nml_wrk_conf`

	struct nml_core core;
	void (*on_accept)(void *boss, ffsock csock, ffsockaddr *peer);
	void (*on_complete)(void *boss, ffsock sk, struct zzkevent *kev);
	void *boss;

	void (*cl_wake)(nml_socks_sv_conn *c);
	void (*cl_destroy)(nml_socks_sv_conn *c);

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
		uint	reuse_port :1;
		uint	v6_only :1;
	} server;

	const nml_socks_sv_component **chain;

	uint connect_timeout_sec;

	struct {
		uint buf_size;
		uint timeout_sec;
	} receive;

	struct {
		uint buf_size;
		uint timeout_sec;
	} send;

	fffd access_log_fd;
	uint debug_data_dump_len;
	uint allow_all_targets :1;
};

struct nml_socks_sv_component {
	int		(*open)(nml_socks_sv_conn *c);
	void	(*close)(nml_socks_sv_conn *c);
	int		(*process)(nml_socks_sv_conn *c);
	char	name[16];
};

typedef struct nml_socks_server nml_socks_server;
FF_EXTERN nml_socks_server* nml_socks_server_create();
FF_EXTERN void nml_socks_server_free(nml_socks_server *s);
FF_EXTERN int nml_socks_server_conf(nml_socks_server *s, struct nml_socks_server_conf *conf);
FF_EXTERN int nml_socks_server_run(nml_socks_server *s);
FF_EXTERN void nml_socks_server_stop(nml_socks_server *s);
