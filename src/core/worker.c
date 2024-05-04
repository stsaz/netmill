/** netmill: core interface implementation
2023, Simon Zolin */

#include <netmill.h>
#include <util/kq.h>
#include <util/kq-tq.h>
#include <util/kq-timer.h>
#include <util/kcq.h>
#include <util/kq-kcq.h>
#include <ffsys/perf.h>

#define WK_SYSERR(w, ...) \
	w->conf.log(w->conf.log_obj, NML_LOG_SYSERR, w->conf.log_ctx, NULL, __VA_ARGS__)

#define WK_DEBUG(w, ...) \
do { \
	if (w->conf.log_level >= NML_LOG_DEBUG) \
		w->conf.log(w->conf.log_obj, NML_LOG_DEBUG, w->conf.log_ctx, NULL, __VA_ARGS__); \
} while (0)

struct nml_wrk {
	struct nml_wrk_conf conf;
	struct zzkq kq;

	struct zzkq_kcq kq_kcq;

	fftimerqueue timer_q;
	struct zzkq_timer kq_timer;
	uint timer_now_ms;
	fftime date_now;
	char date_buf[FFS_LEN("0000-00-00T00:00:00.000")+1];

	fftaskqueue tq;
	struct zzkq_tq kq_tq;
};


/** Get cached calendar UTC date */
static fftime nml_wrk_date(void *p, ffstr *dts)
{
	struct nml_wrk *w = p;
	fftime t = w->date_now;
	if (dts) {
		ffstr_set(dts, w->date_buf, sizeof(w->date_buf)-1);
	}

	return t;
}

static void wk_time_update(struct nml_wrk *w)
{
	fftime t = fftime_monotonic();
	w->timer_now_ms = t.sec*1000 + t.nsec/1000000;

	fftime_now(&w->date_now);
	w->date_now.sec += FFTIME_1970_SECONDS;

	ffdatetime dt;
	fftime_split1(&dt, &w->date_now);
	fftime_tostr1(&dt, w->date_buf, sizeof(w->date_buf), FFTIME_DATE_YMD | FFTIME_HMS_MSEC);
	w->date_buf[10] = 'T';

	if (w->conf.log_date_buffer)
		ffmem_copy(w->conf.log_date_buffer, w->date_buf, sizeof(w->date_buf));
}

static void nml_wrk_ontimer(struct nml_wrk *w)
{
	wk_time_update(w);
	fftimerqueue_process(&w->timer_q, w->timer_now_ms);
	fftimer_consume(w->kq_timer.timer);
}

/** Add/restart/remove periodic/one-shot timer */
static void nml_wrk_timer(void *p, nml_timer *tmr, int interval_msec, fftimerqueue_func func, void *param)
{
	struct nml_wrk *w = p;
	if (!interval_msec) {
		if (fftimerqueue_remove(&w->timer_q, tmr))
			WK_DEBUG(w, "timer remove: %p", tmr);
		return;
	}

	fftimerqueue_add(&w->timer_q, tmr, w->timer_now_ms, interval_msec, func, param);
	WK_DEBUG(w, "timer add: %p %d", tmr, interval_msec);
}

static struct zzkevent* nml_wrk_kev_new(void *p)
{
	struct nml_wrk *w = p;
	struct zzkevent *kev = zzkq_kev_alloc(&w->kq);
	if (kev && w->conf.kcq_sq)
		zzkqkcq_kev_attach(&w->kq_kcq, kev);
	return kev;
}

static void nml_wrk_kev_free(void *p, struct zzkevent *kev)
{
	if (!kev) return;

	struct nml_wrk *w = p;
	ffkcall_cancel(&kev->kcall);
	return zzkq_kev_free(&w->kq, kev);
}

static int nml_wrk_kq_attach(void *p, ffsock sk, struct zzkevent *kev, void *obj)
{
	struct nml_wrk *w = p;
	kev->obj = obj;
	return zzkq_attach(&w->kq, (fffd)sk, kev);
}

static ffkq nml_wrk_kq(void *p)
{
	struct nml_wrk *w = p;
	return w->kq.kq;
}

static void nml_wrk_task(void *p, nml_task *t, uint flags)
{
	struct nml_wrk *w = p;

	if (!flags) {
		fftaskqueue_del(&w->tq, t);
		WK_DEBUG(w, "task remove: %p", t);
		return;
	}

	if (zzkq_tq_post(&w->kq_tq, t))
		WK_SYSERR(w, "zzkq_tq_post");
	WK_DEBUG(w, "task add: %p", t);
}

static const struct nml_core wrk_core_if = {
	.kev_new = nml_wrk_kev_new,
	.kev_free = nml_wrk_kev_free,
	.kq_attach = nml_wrk_kq_attach,
	.kq = nml_wrk_kq,
	.timer = nml_wrk_timer,
	.task = nml_wrk_task,
	.date = nml_wrk_date,
};


static void nml_worker_destroy(struct nml_wrk *w)
{
	if (!w) return;

	zzkqkcq_disconnect(&w->kq_kcq, w->kq.kq);
	zzkq_timer_destroy(&w->kq_timer, w->kq.kq);
	zzkq_destroy(&w->kq);
	ffmem_free(w);
}

static struct nml_wrk* nml_worker_create(nml_core *core)
{
	struct nml_wrk *w = ffmem_new(struct nml_wrk);
	zzkq_timer_init(&w->kq_timer);
	zzkqkcq_init(&w->kq_kcq);
	*core = wrk_core_if;
	return w;
}

static int nml_worker_conf(struct nml_wrk *w, struct nml_wrk_conf *conf)
{
	w->conf = *conf;
	wk_time_update(w);

	struct zzkq_conf kc = {
		.log_level = w->conf.log_level,
		.log = w->conf.log,
		.log_obj = w->conf.log_obj,
		.log_ctx = w->conf.log_ctx,

		.events_wait = w->conf.events_num,
		.max_objects = w->conf.max_connections,
	};
	if (zzkq_create(&w->kq, &kc))
		return -1;

	if (w->conf.kcq_sq
		&& zzkqkcq_connect(&w->kq_kcq, w->kq.kq, w->conf.max_connections, w->conf.kcq_sq, w->conf.kcq_sq_sem))
		return -1;

	fftimerqueue_init(&w->timer_q);
	if (zzkq_timer_create(&w->kq_timer, w->kq.kq, w->conf.timer_interval_msec, (void*)nml_wrk_ontimer, w))
		return -1;

	fftaskqueue_init(&w->tq);
	if (zzkq_tq_attach(&w->kq_tq, w->kq.kq, &w->tq))
		return -1;
	return 0;
}

static int nml_worker_run(struct nml_wrk *w)
{
	return zzkq_run(&w->kq);
}

static void nml_worker_stop(struct nml_wrk *w)
{
	zzkq_stop(&w->kq);
}

const struct nml_worker_if nml_worker_interface = {
	nml_worker_create,
	nml_worker_destroy,
	nml_worker_conf,
	nml_worker_run,
	nml_worker_stop,
};
