/** netmill: http-server: server
2023, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/kcq.h>
#include <util/kq-kcq.h>
#include <util/kq-timer.h>
#include <util/kq-tq.h>
#include <FFOS/perf.h>

struct nml_http_server {
	struct nml_http_server_conf conf;
	struct zzkq kq;
	struct zzkq_kcq kq_kcq;
	uint worker_stop;

	struct ffkcallqueue kcq;
	struct zzkevent kcq_kev;

	fftimerqueue timer_q;
	struct zzkq_timer kq_timer;
	uint timer_now_ms;
	fftime date_now;
	char date_buf[FFS_LEN("0000-00-00T00:00:00.000")+1];

	fftaskqueue tq;
	struct zzkq_tq kq_tq;

	nml_tcp_listener *ls;
};

#define sv_syserrlog(s, ...) \
	s->conf.log(s->conf.log_obj, NML_LOG_SYSERR, "http-sv", NULL, __VA_ARGS__)

#define sv_warnlog(s, ...) \
	s->conf.log(s->conf.log_obj, NML_LOG_WARN, "http-sv", NULL, __VA_ARGS__)

#define sv_verblog(s, ...) \
do { \
	if (s->conf.log_level >= NML_LOG_VERBOSE) \
		s->conf.log(s->conf.log_obj, NML_LOG_VERBOSE, "http-sv", NULL, __VA_ARGS__); \
} while (0)

#define sv_dbglog(s, ...) \
do { \
	if (s->conf.log_level >= NML_LOG_DEBUG) \
		s->conf.log(s->conf.log_obj, NML_LOG_DEBUG, "http-sv", NULL, __VA_ARGS__); \
} while (0)

nml_http_server* nml_http_server_new()
{
	nml_http_server *s = ffmem_new(struct nml_http_server);
	zzkq_timer_init(&s->kq_timer);
	zzkqkcq_init(&s->kq_kcq);
	return s;
}

void nml_http_server_free(nml_http_server *s)
{
	if (s == NULL) return;

	zzkqkcq_disconnect(&s->kq_kcq, s->kq.kq);
	zzkq_timer_destroy(&s->kq_timer, s->kq.kq);
	zzkq_destroy(&s->kq);
	nml_tcp_listener_free(s->ls);
	ffmem_free(s);
}

/** Get cached calendar UTC date */
static fftime sv_date(void *p, ffstr *dts)
{
	nml_http_server *s = p;
	fftime t = s->date_now;
	if (dts != NULL) {
		ffstr_set(dts, s->date_buf, sizeof(s->date_buf)-1);
	}

	return t;
}

static void time_update(nml_http_server *s)
{
	fftime_now(&s->date_now);
	s->date_now.sec += FFTIME_1970_SECONDS;

	ffdatetime dt;
	fftime_split1(&dt, &s->date_now);
	fftime_tostr1(&dt, s->date_buf, sizeof(s->date_buf), FFTIME_DATE_YMD | FFTIME_HMS_MSEC);
	s->date_buf[10] = 'T';

	if (s->conf.log_date_buffer != NULL)
		ffmem_copy(s->conf.log_date_buffer, s->date_buf, sizeof(s->date_buf));
}

static void sv_ontimer(nml_http_server *s)
{
	time_update(s);

	fftime t = fftime_monotonic();
	s->timer_now_ms = t.sec*1000 + t.nsec/1000000;
	fftimerqueue_process(&s->timer_q, s->timer_now_ms);
	fftimer_consume(s->kq_timer.timer);
}

/** Add/restart/remove periodic/one-shot timer */
static void sv_timer(void *p, nml_timer *tmr, int interval_msec, fftimerqueue_func func, void *param)
{
	nml_http_server *s = p;
	if (interval_msec == 0) {
		if (fftimerqueue_remove(&s->timer_q, tmr))
			sv_dbglog(s, "timer remove: %p", tmr);
		return;
	}

	fftimerqueue_add(&s->timer_q, tmr, s->timer_now_ms, interval_msec, func, param);
	sv_dbglog(s, "timer add: %p %d", tmr, interval_msec);
}

static struct zzkevent* sv_kev_new(void *p)
{
	nml_http_server *s = p;
	struct zzkevent *kev = zzkq_kev_alloc(&s->kq);
	if (kev != NULL && s->conf.kcq_sq != NULL)
		zzkqkcq_kev_attach(&s->kq_kcq, kev);
	return kev;
}

static void sv_kev_free(void *p, struct zzkevent *kev)
{
	if (kev == NULL) return;

	nml_http_server *s = p;
	ffkcall_cancel(&kev->kcall);
	return zzkq_kev_free(&s->kq, kev);
}

static int sv_kq_attach(void *p, ffsock sk, struct zzkevent *kev, void *obj)
{
	nml_http_server *s = p;
	kev->obj = obj;
	return zzkq_attach(&s->kq, (fffd)sk, kev);
}

static void sv_task(void *p, nml_task *t, uint flags)
{
	nml_http_server *s = p;
	if (flags == 0) {
		fftaskqueue_del(&s->tq, t);
		sv_dbglog(s, "task remove: %p", t);
		return;
	}
	if (!!zzkq_tq_post(&s->kq_tq, t))
		sv_syserrlog(s, "zzkq_tq_post");
	sv_dbglog(s, "task add: %p", t);
}

static const struct nml_core core = {
	.kev_new = sv_kev_new,
	.kev_free = sv_kev_free,
	.kq_attach = sv_kq_attach,
	.timer = sv_timer,
	.task = sv_task,
	.date = sv_date,
};

extern void cl_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_http_server_conf *conf);

static void sv_on_accept(void *p, ffsock csock, ffsockaddr *peer)
{
	nml_http_server *s = p;
	uint conn_id = ffint_fetch_add(s->conf.server.conn_id_counter, 1);
	cl_start(csock, peer, conn_id, &s->conf);
}

static void sv_on_complete(void *p, ffsock sk, struct zzkevent *kev)
{
	nml_http_server *s = p;
	ffsock_close(sk);
	if (kev != NULL) {
		ffkcall_cancel(&kev->kcall);
		zzkq_kev_free(&s->kq, kev);
	}
}

static void sv_log(void *opaque, ffuint level, const char *ctx, const char *id, const char *format, ...)
{}

/** Initialize default config */
static void sv_conf_init(struct nml_http_server_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = sv_log;

	conf->core = core;

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

	conf->debug_data_dump_len = 80;
}

int nml_http_server_conf(nml_http_server *s, struct nml_http_server_conf *conf)
{
	if (s == NULL) {
		sv_conf_init(conf);
		return 0;
	}

	s->conf = *conf;
	s->conf.on_complete = sv_on_complete;
	s->conf.boss = s;

	time_update(s);

	struct zzkq_conf kc = {
		.log_level = s->conf.log_level,
		.log = s->conf.log,
		.log_obj = s->conf.log_obj,
		.log_ctx = "http-sv",

		.events_wait = s->conf.server.events_num,
		.max_objects = s->conf.server.max_connections,
	};
	if (!!zzkq_create(&s->kq, &kc))
		return -1;

	if (s->conf.kcq_sq != NULL
		&& !!zzkqkcq_connect(&s->kq_kcq, s->kq.kq, s->conf.server.max_connections, s->conf.kcq_sq, s->conf.kcq_sq_sem))
		return -1;

	fftimerqueue_init(&s->timer_q);
	if (!!zzkq_timer_create(&s->kq_timer, s->kq.kq, s->conf.server.timer_interval_msec, (void*)sv_ontimer, s))
		return -1;

	fftaskqueue_init(&s->tq);
	if (!!zzkq_tq_attach(&s->kq_tq, s->kq.kq, &s->tq))
		return -1;

	struct nml_tcp_listener_conf lc;
	nml_tcp_listener_conf(NULL, &lc);

	lc.log_level = s->conf.log_level;
	lc.log = s->conf.log;
	lc.log_obj = s->conf.log_obj;

	lc.core = s->conf.core;
	lc.on_accept = sv_on_accept;
	lc.boss = s;

	lc.fdlimit_timeout_sec = s->conf.server.fdlimit_timeout_sec;
	lc.backlog = s->conf.server.listen_backlog;
	lc.addr = s->conf.server.listen_addresses[0];
	lc.reuse_port = s->conf.server.reuse_port;
	lc.v6_only = s->conf.server.v6_only;

	if (NULL == (s->ls = nml_tcp_listener_new()))
		return -1;
	return nml_tcp_listener_conf(s->ls, &lc);
}

int nml_http_server_run(nml_http_server *s)
{
	if (!!nml_tcp_listener_run(s->ls))
		return -1;

	return zzkq_run(&s->kq);
}

void nml_http_server_stop(nml_http_server *s)
{
	zzkq_stop(&s->kq);
}
