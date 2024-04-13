/** netmill: dns-server: receive request
2023, Simon Zolin */

#include <netmill.h>

extern void ds_run(nml_dns_sv_conn *c);

struct nml_dns_server {
	struct nml_dns_server_conf *conf;
	struct nml_wrk *wrk;
	nml_udp_listener *ls;
};

nml_dns_server* nml_dns_server_create()
{
	nml_dns_server *s = ffmem_new(struct nml_dns_server);
	return s;
}

void nml_dns_server_free(nml_dns_server *s)
{
	if (!s) return;

	if (s->wrk)
		s->conf->server.wif->free(s->wrk);
	if (s->ls)
		s->conf->server.lsif->free(s->ls);
	ffmem_free(s);
}

extern void ds_start(struct nml_dns_server_conf *conf, uint conn_id, ffsock sk, ffsockaddr *addr, ffstr request);

static void sv_on_recv_udp(void *w, ffsock sk, ffsockaddr *addr, ffstr request)
{
	nml_dns_server *s = ((struct nml_wrk_conf*)w)->opaque;
	uint conn_id = ffint_fetch_add(s->conf->server.conn_id_counter, 1);
	ds_start(s->conf, conn_id, sk, addr, request);
}

static void sv_log(void *opaque, ffuint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void sv_conf_init(struct nml_dns_server_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = sv_log;

	conf->wake = ds_run;

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
	if (!s) {
		sv_conf_init(conf);
		return 0;
	}

	NML_ASSERT(conf->server.wif);
	NML_ASSERT(conf->server.lsif);
	if (!conf->chain)
		return -1;

	s->conf = conf;

	s->wrk = s->conf->server.wif->create(&s->conf->core);

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
	if (s->conf->server.wif->conf(s->wrk, &wc))
		return -1;

	s->conf->boss = s->wrk;

	struct nml_udp_listener_conf lc;
	s->conf->server.lsif->conf(NULL, &lc);

	lc.log_level = conf->log_level;
	lc.log = conf->log;
	lc.log_obj = conf->log_obj;

	lc.core = s->conf->core;
	lc.on_recv_udp = sv_on_recv_udp;
	lc.opaque = s->wrk;

	lc.addr = conf->server.listen_addresses[0];
	lc.reuse_port = conf->server.reuse_port;
	lc.v6_only = conf->server.v6_only;

	if (!(s->ls = s->conf->server.lsif->create()))
		return -1;
	return s->conf->server.lsif->conf(s->ls, &lc);
}

int nml_dns_server_run(nml_dns_server *s)
{
	if (s->conf->server.lsif->run(s->ls))
		return -1;

	return s->conf->server.wif->run(s->wrk);
}

void nml_dns_server_stop(nml_dns_server *s)
{
	s->conf->server.wif->stop(s->wrk);
}
