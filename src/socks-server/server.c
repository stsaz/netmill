/** netmill: SOCKS server
2026, Simon Zolin */

#include <netmill-socks.h>
#include <ffsys/std.h>

struct nml_socks_server {
	struct nml_socks_server_conf conf;
	nml_wrk *wrk;
	nml_tcp_listener *ls;
};

nml_socks_server* nml_socks_server_create()
{
	nml_socks_server *s = ffmem_new(struct nml_socks_server);
	return s;
}

void nml_socks_server_free(nml_socks_server *s)
{
	if (!s) return;

	s->conf.server.wif->free(s->wrk);
	s->conf.server.lsif->free(s->ls);
	ffmem_free(s);
}

extern void sksv_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_socks_server_conf *conf);

static void sksv_on_accept(void *w, ffsock csock, ffsockaddr *peer)
{
	nml_socks_server *s = ((struct nml_wrk_conf*)w)->opaque;
	uint conn_id = ffint_fetch_add(s->conf.server.conn_id_counter, 1);
	sksv_start(csock, peer, conn_id, &s->conf);
}

static void sksv_on_complete(void *w, ffsock sk, struct zzkevent *kev)
{
	nml_socks_server *s = ((struct nml_wrk_conf*)w)->opaque;
	ffsock_close(sk);
	if (kev)
		s->conf.core.kev_free(s->wrk, kev);
}

static void sksv_log(void *opaque, uint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void sksv_conf_init(struct nml_socks_server_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = sksv_log;

	static struct nml_address a[2];
	a[0].port = 1080;
	conf->server.listen_addresses = a;
	conf->server.events_num = 1024;
	conf->server.fdlimit_timeout_sec = 10;
	conf->server.timer_interval_msec = 250;
	conf->server.max_connections = 10000;
	conf->server.conn_id_counter = &conf->server._conn_id_counter_default;
	conf->server.listen_backlog = SOMAXCONN;

	conf->connect_timeout_sec = 10;
	conf->receive.buf_size = 4*1024;
	conf->receive.timeout_sec = 65;
	conf->send.buf_size = 4*1024;
	conf->send.timeout_sec = 65;

	conf->access_log_fd = ffstderr;
	conf->debug_data_dump_len = 80;
}

static nml_wrk* sksv_worker(nml_socks_server *s)
{
	struct nml_socks_server_conf *hc = &s->conf;
	nml_wrk *w = hc->server.wif->create(&hc->core);
	struct nml_wrk_conf wc = {
		.opaque = s,

		.log_level = hc->log_level,
		.log = hc->log,
		.log_obj = hc->log_obj,
		.log_ctx = "socks-sv",
		.log_date_buffer = hc->log_date_buffer,

		.timer_interval_msec = hc->server.timer_interval_msec,
		.events_num = hc->server.events_num,
		.max_connections = hc->server.max_connections,
	};
	if (hc->server.wif->conf(w, &wc)) {
		hc->server.wif->free(w);
		return NULL;
	}
	return w;
}

int nml_socks_server_conf(nml_socks_server *s, struct nml_socks_server_conf *conf)
{
	if (!s) {
		sksv_conf_init(conf);
		return 0;
	}

	NML_ASSERT(conf->chain);
	NML_ASSERT(conf->server.wif);
	NML_ASSERT(conf->server.lsif);

	s->conf = *conf;

	s->conf.on_complete = sksv_on_complete;
	if (!s->conf.boss
		&& !(s->conf.boss = sksv_worker(s)))
		return -1;
	s->wrk = s->conf.boss;

	struct nml_tcp_listener_conf lc;
	s->conf.server.lsif->conf(NULL, &lc);

	lc.log_level = s->conf.log_level;
	lc.log = s->conf.log;
	lc.log_obj = s->conf.log_obj;

	lc.core = s->conf.core;
	lc.on_accept = sksv_on_accept;
	lc.opaque = s->wrk;

	lc.fdlimit_timeout_sec = s->conf.server.fdlimit_timeout_sec;
	lc.backlog = s->conf.server.listen_backlog;
	lc.addr = s->conf.server.listen_addresses[0];
	lc.reuse_port = s->conf.server.reuse_port;
	lc.v6_only = s->conf.server.v6_only;

	if (!(s->ls = s->conf.server.lsif->create()))
		return -1;
	return s->conf.server.lsif->conf(s->ls, &lc);
}

int nml_socks_server_run(nml_socks_server *s)
{
	if (s->conf.server.lsif->run(s->ls))
		return -1;

	return s->conf.server.wif->run(s->wrk);
}

void nml_socks_server_stop(nml_socks_server *s)
{
	s->conf.server.wif->stop(s->wrk);
}
