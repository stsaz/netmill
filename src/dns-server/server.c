/** netmill: dns-server: receive request
2023, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/kcq.h>
#include <util/kq-kcq.h>
#include <util/kq-timer.h>
#include <util/kq-tq.h>
#include <FFOS/perf.h>

#define sv_syserrlog(s, ...) \
	s->conf->log(s->conf->log_obj, NML_LOG_SYSERR, "dns-sv", NULL, __VA_ARGS__)

#define sv_dbglog(s, ...) \
do { \
	if (s->conf->log_level >= NML_LOG_DEBUG) \
		s->conf->log(s->conf->log_obj, NML_LOG_DEBUG, "dns-sv", NULL, __VA_ARGS__); \
} while (0)

extern void cl_filters_run(nml_dns_sv_conn *c);

struct nml_dns_server {
	struct nml_dns_server_conf *conf;
	struct zzkq kq;
	uint worker_stop;

	fftimerqueue timer_q;
	struct zzkq_timer kq_timer;
	uint timer_now_ms;
	fftime date_now;
	char date_buf[FFS_LEN("0000-00-00T00:00:00.000")+1];

	fftaskqueue tq;
	struct zzkq_tq kq_tq;

	nml_udp_listener *ls;
};

nml_dns_server* nml_dns_server_new()
{
	nml_dns_server *s = ffmem_new(struct nml_dns_server);
	zzkq_timer_init(&s->kq_timer);
	return s;
}

void nml_dns_server_free(nml_dns_server *s)
{
	if (s == NULL) return;

	zzkq_timer_destroy(&s->kq_timer, s->kq.kq);
	zzkq_destroy(&s->kq);
	nml_udp_listener_free(s->ls);
	ffmem_free(s);
}

/** Get cached calendar UTC date */
static fftime sv_date(void *p, ffstr *dts)
{
	nml_dns_server *s = p;
	fftime t = s->date_now;
	if (dts != NULL) {
		ffstr_set(dts, s->date_buf, sizeof(s->date_buf)-1);
	}

	return t;
}

static void time_update(nml_dns_server *s)
{
	fftime t = fftime_monotonic();
	s->timer_now_ms = t.sec*1000 + t.nsec/1000000;

	fftime_now(&s->date_now);
	s->date_now.sec += FFTIME_1970_SECONDS;

	ffdatetime dt;
	fftime_split1(&dt, &s->date_now);
	fftime_tostr1(&dt, s->date_buf, sizeof(s->date_buf), FFTIME_DATE_YMD | FFTIME_HMS_MSEC);
	s->date_buf[10] = 'T';

	if (s->conf->log_date_buffer != NULL)
		ffmem_copy(s->conf->log_date_buffer, s->date_buf, sizeof(s->date_buf));
}

static void sv_ontimer(nml_dns_server *s)
{
	time_update(s);

	fftimerqueue_process(&s->timer_q, s->timer_now_ms);
	fftimer_consume(s->kq_timer.timer);
}

/** Add/restart/remove periodic/one-shot timer */
static void sv_timer(void *p, nml_timer *tmr, int interval_msec, fftimerqueue_func func, void *param)
{
	nml_dns_server *s = p;
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
	nml_dns_server *s = p;
	struct zzkevent *kev = zzkq_kev_alloc(&s->kq);
	return kev;
}

static void sv_kev_free(void *p, struct zzkevent *kev)
{
	if (kev == NULL) return;

	nml_dns_server *s = p;
	ffkcall_cancel(&kev->kcall);
	return zzkq_kev_free(&s->kq, kev);
}

static int sv_kq_attach(void *p, ffsock sk, struct zzkevent *kev, void *obj)
{
	nml_dns_server *s = p;
	kev->obj = obj;
	return zzkq_attach(&s->kq, (fffd)sk, kev);
}

static ffkq sv_kq(void *p)
{
	nml_dns_server *s = p;
	return s->kq.kq;
}

static void sv_task(void *p, nml_task *t, uint flags)
{
	nml_dns_server *s = p;
	if (flags == 0) {
		fftaskqueue_del(&s->tq, t);
		sv_dbglog(s, "task remove: %p", t);
		return;
	}
	if (zzkq_tq_post(&s->kq_tq, t))
		sv_syserrlog(s, "zzkq_tq_post");
	sv_dbglog(s, "task add: %p", t);
}

static const struct nml_core core = {
	.kev_new = sv_kev_new,
	.kev_free = sv_kev_free,
	.kq_attach = sv_kq_attach,
	.kq = sv_kq,
	.timer = sv_timer,
	.task = sv_task,
	.date = sv_date,
};

extern void dns_cl_start(struct nml_dns_server_conf *conf, uint conn_id, ffsock sk, ffsockaddr *addr, ffstr request);

static void sv_on_recv_udp(void *boss, ffsock sk, ffsockaddr *addr, ffstr request)
{
	nml_dns_server *s = boss;
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

	conf->core = core;
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

	s->conf = conf;
	s->conf->boss = s;

	time_update(s);

	struct zzkq_conf kc = {
		.log_level = conf->log_level,
		.log = conf->log,
		.log_obj = conf->log_obj,
		.log_ctx = "dns-sv",

		.events_wait = conf->server.events_num,
		.max_objects = conf->server.max_connections,
	};
	if (zzkq_create(&s->kq, &kc))
		return -1;

	fftimerqueue_init(&s->timer_q);
	if (zzkq_timer_create(&s->kq_timer, s->kq.kq, conf->server.timer_interval_msec, (void*)sv_ontimer, s))
		return -1;

	fftaskqueue_init(&s->tq);
	if (zzkq_tq_attach(&s->kq_tq, s->kq.kq, &s->tq))
		return -1;

	struct nml_udp_listener_conf lc;
	nml_udp_listener_conf(NULL, &lc);

	lc.log_level = conf->log_level;
	lc.log = conf->log;
	lc.log_obj = conf->log_obj;

	lc.core = conf->core;
	lc.on_recv_udp = sv_on_recv_udp;
	lc.boss = s;

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

	return zzkq_run(&s->kq);
}

void nml_dns_server_stop(nml_dns_server *s)
{
	zzkq_stop(&s->kq);
}
