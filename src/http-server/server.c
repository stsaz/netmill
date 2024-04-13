/** netmill: http-server: server
2023, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/kcq.h>
#include <util/kq-kcq.h>
#include <util/kq-timer.h>
#include <util/kq-tq.h>
#include <ffsys/perf.h>
#include <ffsys/std.h>

struct nml_http_server {
	struct nml_http_server_conf conf;
	nml_wrk *wrk;
	nml_tcp_listener *ls;
};

nml_http_server* nml_http_server_create()
{
	nml_http_server *s = ffmem_new(struct nml_http_server);
	return s;
}

void nml_http_server_free(nml_http_server *s)
{
	if (!s) return;

	s->conf.server.wif->free(s->wrk);
	s->conf.server.lsif->free(s->ls);
	ffmem_free(s);
}

extern void hs_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_http_server_conf *conf);

static void sv_on_accept(void *w, ffsock csock, ffsockaddr *peer)
{
	nml_http_server *s = ((struct nml_wrk_conf*)w)->opaque;
	uint conn_id = ffint_fetch_add(s->conf.server.conn_id_counter, 1);
	hs_start(csock, peer, conn_id, &s->conf);
}

static void sv_on_complete(void *w, ffsock sk, struct zzkevent *kev)
{
	nml_http_server *s = ((struct nml_wrk_conf*)w)->opaque;
	ffsock_close(sk);
	if (kev)
		s->conf.core.kev_free(s->wrk, kev);
}

static void sv_log(void *opaque, uint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void sv_conf_init(struct nml_http_server_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = sv_log;

	conf->core = conf->core;

	static struct nml_address a[2];
	a[0].port = 80;
	conf->server.listen_addresses = a;
	conf->server.events_num = 1024;
	conf->server.fdlimit_timeout_sec = 10;
	conf->server.timer_interval_msec = 250;
	conf->server.max_connections = 10000;
	conf->server.conn_id_counter = &conf->server._conn_id_counter_default;
	conf->server.listen_backlog = SOMAXCONN;

	conf->max_keep_alive_reqs = 100;

	conf->receive.buf_size = 4*1024;
	conf->receive.timeout_sec = 65;
	conf->recv_body.buf_size = 64*1024;
	conf->recv_body.timeout_sec = 65;

	ffstr_setz(&conf->fs.index_filename, "index.html");
	conf->fs.file_buf_size = 16*1024;

	conf->response.buf_size = 4*1024;
	ffstr_setz(&conf->response.server_name, "netmill");

	conf->send.tcp_nodelay = 1;
	conf->send.timeout_sec = 65;

	conf->access_log_fd = ffstderr;

	conf->debug_data_dump_len = 80;
}

int nml_http_server_conf(nml_http_server *s, struct nml_http_server_conf *conf)
{
	if (!s) {
		sv_conf_init(conf);
		return 0;
	}

	NML_ASSERT(conf->chain);
	NML_ASSERT(conf->server.wif);
	NML_ASSERT(conf->server.lsif);

	s->conf = *conf;

	s->wrk = s->conf.server.wif->create(&s->conf.core);
	struct nml_wrk_conf wc = {
		.opaque = s,

		.log_level = conf->log_level,
		.log = conf->log,
		.log_obj = conf->log_obj,
		.log_ctx = "http-sv",
		.log_date_buffer = conf->log_date_buffer,

		.kcq_sq = conf->kcq_sq,
		.kcq_sq_sem = conf->kcq_sq_sem,

		.timer_interval_msec = conf->server.timer_interval_msec,
		.events_num = conf->server.events_num,
		.max_connections = conf->server.max_connections,
	};
	if (s->conf.server.wif->conf(s->wrk, &wc))
		return -1;

	s->conf.on_complete = sv_on_complete;
	s->conf.boss = s->wrk;

	struct nml_tcp_listener_conf lc;
	s->conf.server.lsif->conf(NULL, &lc);

	lc.log_level = s->conf.log_level;
	lc.log = s->conf.log;
	lc.log_obj = s->conf.log_obj;

	lc.core = s->conf.core;
	lc.on_accept = sv_on_accept;
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

int nml_http_server_run(nml_http_server *s)
{
	if (s->conf.server.lsif->run(s->ls))
		return -1;

	return s->conf.server.wif->run(s->wrk);
}

void nml_http_server_stop(nml_http_server *s)
{
	s->conf.server.wif->stop(s->wrk);
}

const struct nml_http_server_if nml_http_server_interface = {
	nml_http_server_create,
	nml_http_server_free,
	nml_http_server_conf,
	nml_http_server_run,
	nml_http_server_stop,
};
