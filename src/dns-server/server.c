/** netmill: dns-server: receive request
2023, Simon Zolin */

#include <netmill.h>

extern void cl_filters_run(nml_dns_sv_conn *c);

struct nml_dns_server {
	struct nml_dns_server_conf *conf;
	struct nml_wrk *wrk;
	nml_udp_listener *ls;
};

nml_dns_server* nml_dns_server_new()
{
	nml_dns_server *s = ffmem_new(struct nml_dns_server);
	s->wrk = nml_wrk_new();
	return s;
}

void nml_dns_server_free(nml_dns_server *s)
{
	if (s == NULL) return;

	nml_wrk_free(s->wrk);
	nml_udp_listener_free(s->ls);
	ffmem_free(s);
}

extern void dns_cl_start(struct nml_dns_server_conf *conf, uint conn_id, ffsock sk, ffsockaddr *addr, ffstr request);

static void sv_on_recv_udp(void *w, ffsock sk, ffsockaddr *addr, ffstr request)
{
	nml_dns_server *s = ((struct nml_wrk_conf*)w)->opaque;
	uint conn_id = ffint_fetch_add(s->conf->server.conn_id_counter, 1);
	dns_cl_start(s->conf, conn_id, sk, addr, request);
}

static void sv_log(void *opaque, ffuint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void sv_conf_init(struct nml_dns_server_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = sv_log;

	conf->core = nml_wrk_core_if;
	conf->wake = cl_filters_run;

	static struct nml_address a[2];
	a[0].port = 53;
	conf->server.listen_addresses = a;
	conf->server.max_connections = 10000;
	conf->server.events_num = 1024;
	conf->server.timer_interval_msec = 100;
	conf->server.conn_id_counter = &conf->server._conn_id_counter_default;

	conf->hosts.rewrite_ttl = 60;
	conf->hosts.block_ttl = 60;

	conf->upstreams.read_timeout_msec = 300;
	conf->upstreams.resend_attempts = 2;

	conf->debug_data_dump_len = 80;
}

int nml_dns_server_conf(nml_dns_server *s, struct nml_dns_server_conf *conf)
{
	if (s == NULL) {
		sv_conf_init(conf);
		return 0;
	}

	if (!conf->chain)
		return -1;

	s->conf = conf;

	struct nml_wrk_conf wc = {
		.opaque = s,

		.log_level = conf->log_level,
		.log = conf->log,
		.log_obj = conf->log_obj,
		.log_ctx = "dns-sv",
		.log_date_buffer = conf->log_date_buffer,

		.timer_interval_msec = conf->server.timer_interval_msec,
		.events_num = conf->server.events_num,
		.max_connections = conf->server.max_connections,
	};
	if (nml_wrk_conf(s->wrk, &wc))
		return -1;

	s->conf->boss = s->wrk;

	struct nml_udp_listener_conf lc;
	nml_udp_listener_conf(NULL, &lc);

	lc.log_level = conf->log_level;
	lc.log = conf->log;
	lc.log_obj = conf->log_obj;

	lc.core = conf->core;
	lc.on_recv_udp = sv_on_recv_udp;
	lc.boss = s->wrk;

	lc.addr = conf->server.listen_addresses[0];
	lc.reuse_port = conf->server.reuse_port;
	lc.v6_only = conf->server.v6_only;

	if (NULL == (s->ls = nml_udp_listener_new()))
		return -1;
	return nml_udp_listener_conf(s->ls, &lc);
}

int nml_dns_server_run(nml_dns_server *s)
{
	if (nml_udp_listener_run(s->ls))
		return -1;

	return nml_wrk_run(s->wrk);
}

void nml_dns_server_stop(nml_dns_server *s)
{
	nml_wrk_stop(s->wrk);
}
