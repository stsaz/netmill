/** netmill: tester
2023, Simon Zolin */

#include <ffsys/test.h>
#include <netmill.h>
#include <util/kq.h>
#include <util/kq-kcq.h>
#include <util/kq-tq.h>
#include <util/kq-timer.h>
#include <util/kcq.h>
#include <util/log.h>
#include <util/taskqueue.h>
#include <ffsys/timerqueue.h>
#include <ffsys/globals.h>

uint _ffsys_checks_success;
uint _ffsys_keep_running;

struct tester {
	uint test_num, test_data;

	struct {
		struct nml_http_client_conf conf;
		nml_http_client *oc;
	};
	struct {
		struct nml_http_server_conf svconf;
		nml_tcp_listener *ls;
	};

	struct zzlog log;
	struct zzkq kq;

	struct zzkcq kcq;
	struct zzkq_kcq kq_kcq;

	fftaskqueue tq;
	struct zzkq_tq kq_tq;
	fftask tsk;

	fftimerqueue timer_q;
	struct zzkq_timer kq_timer;
};

static void test_log(void *opaque, uint level, const char *ctx, const char *id, const char *fmt, ...)
{
	struct tester *t = opaque;
	va_list va;
	va_start(va, fmt);

	uint flags = level;
	if (level == NML_LOG_SYSFATAL
		|| level == NML_LOG_SYSERR
		|| level == NML_LOG_SYSWARN)
		flags |= ZZLOG_SYS_ERROR;

	zzlog_printv(&t->log, flags, ctx, id, fmt, va);
	va_end(va);
}

static void log_init(struct tester *t)
{
	t->log.fd = ffstdout;
	t->log.stdout_color = 1;

	static const char levels[][8] = {
		"FATAL",
		"ERROR",
		"ERROR",
		"WARN",
		"WARN",
		"INFO",
		"INFO",
		"DEBUG",
		"DEBUG+",
	};
	ffmem_copy(t->log.levels, levels, sizeof(levels));

	static const char colors[][8] = {
		/*NML_LOG_SYSFATAL*/	FFSTD_CLR_B(FFSTD_RED),
		/*NML_LOG_SYSERR*/	FFSTD_CLR(FFSTD_RED),
		/*NML_LOG_ERR*/	FFSTD_CLR(FFSTD_RED),
		/*NML_LOG_SYSWARN*/	FFSTD_CLR(FFSTD_YELLOW),
		/*NML_LOG_WARN*/	FFSTD_CLR(FFSTD_YELLOW),
		/*NML_LOG_INFO*/	FFSTD_CLR(FFSTD_GREEN),
		/*NML_LOG_VERBOSE*/	FFSTD_CLR(FFSTD_GREEN),
		/*NML_LOG_DEBUG*/	"",
		/*NML_LOG_EXTRA*/	FFSTD_CLR_I(FFSTD_BLUE),
	};
	ffmem_copy(t->log.colors, colors, sizeof(colors));
}

static void test_task(void *opaque, nml_task *ts, uint flags)
{
	struct tester *t = opaque;
	if (flags == 0) {
		fftaskqueue_del(&t->tq, ts);
		return;
	}
	zzkq_tq_post(&t->kq_tq, ts);
}

static void test_timer(void *opaque, nml_timer *tmr, int interval_msec, fftimerqueue_func func, void *param)
{
	// struct tester *t = opaque;
}

static struct zzkevent* test_kev_new(void *opaque)
{
	struct tester *t = opaque;
	struct zzkevent *kev = zzkq_kev_alloc(&t->kq);
	if (kev != NULL) {
		zzkqkcq_kev_attach(&t->kq_kcq, kev);
	}
	return kev;
}

static void test_kev_free(void *opaque, struct zzkevent *kev)
{
	struct tester *t = opaque;
	zzkq_kev_free(&t->kq, kev);
}

static int test_kq_attach(void *opaque, ffsock sk, struct zzkevent *kev, void *obj)
{
	struct tester *t = opaque;
	kev->obj = obj;
	return zzkq_attach(&t->kq, sk, kev);
}

static fftime test_date(void *srv, ffstr *dts)
{
	fftime t = {};
	return t;
}

static const struct nml_core core = {
	.kev_new = test_kev_new,
	.kev_free = test_kev_free,
	.kq_attach = test_kq_attach,
	.timer = test_timer,
	.task = test_task,
	.date = test_date,
};

// #include <test/http-client.h>
#include <test/http-proxy.h>

void test_finished(struct tester *t)
{
	nml_http_client_free(t->oc);  t->oc = NULL;
	nml_tcp_listener_free(t->ls);  t->ls = NULL;

	t->test_num++;
	if (t->test_num == 8) {
		zzkq_stop(&t->kq);
		return;
	}

	ffthread_sleep(500);
	// test_http_client(t);
}

int main()
{
	struct tester tt = {};
	struct tester *t = &tt;
	zzkq_init(&t->kq);
	zzkqkcq_init(&t->kq_kcq);

	log_init(t);

	struct zzkq_conf c = {
		.log_level = ZZKQ_LOG_DEBUG,
		.log = (log_print_func)zzlog_print,
		.log_obj = &t->log,
		.log_ctx = "kq",

		.max_objects = 2,
		.events_wait = 10,
	};
	x_sys(!zzkq_create(&t->kq, &c));

	x_sys(!zzkcq_create(&t->kcq, 1, 1, 0));
	x_sys(!zzkqkcq_connect(&t->kq_kcq, t->kq.kq, 1, t->kcq.sq, t->kcq.sem));
	x_sys(!zzkcq_start(&t->kcq));

	fftaskqueue_init(&t->tq);
	zzkq_tq_attach(&t->kq_tq, t->kq.kq, &t->tq);
	fftask_set(&t->tsk, (void*)test_finished, t);

	// fftimerqueue_init(&t->timer_q);
	// x_sys(!zzkq_timer_create(&t->kq_timer, t->kq.kq, 100, NULL, t));

	t->test_num = 1; // first test to run
	// test_http_client(t);
	test_http_proxy(t);

	zzkq_run(&t->kq);
	zzkqkcq_disconnect(&t->kq_kcq, t->kq.kq);
	zzkq_timer_destroy(&t->kq_timer, t->kq.kq);
	zzkq_destroy(&t->kq);
	zzkcq_destroy(&t->kcq);

	fflog("Test checks made: %u", _ffsys_checks_success);
	return 0;
}
