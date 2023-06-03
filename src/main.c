/** netmill: http: startup
2022, Simon Zolin */

#include <netmill.h>
#include <cmd.h>
#include <util/kcq.h>
#include <util/log.h>
#include <FFOS/signal.h>
#include <FFOS/thread.h>
#include <FFOS/ffos-extern.h>
#ifdef FF_UNIX
#include <sys/resource.h>
#endif

struct worker {
	nml_http_server *srv;
	ffthread thd;
};

struct boss {
	ffvec workers; // struct worker[]
	uint conn_id;
	struct zzlog log;
	struct zzkcq kcq;
};

static struct nml_http_sv_conf *conf;
static struct boss *boss;
extern const struct nml_filter* nml_http_server_filters[];
extern const struct nml_filter* nml_http_server_filters_proxy[];

#define sysfatallog(...) \
	zzlog_print(&boss->log, NML_LOG_SYSFATAL, "main", NULL, __VA_ARGS__)
#define syserrlog(...) \
	zzlog_print(&boss->log, NML_LOG_SYSERR, "main", NULL, __VA_ARGS__)
#define dbglog(...) \
do { \
	if (conf->aconf.log_level >= NML_LOG_DEBUG) \
		zzlog_print(&boss->log, NML_LOG_DEBUG, "main", NULL, __VA_ARGS__); \
} while (0)

static int FFTHREAD_PROCCALL wrk_thread(struct worker *w)
{
	dbglog("worker: started");
	return nml_http_server_run(w->srv);
}

static int wrk_start(struct worker *w)
{
	if (FFTHREAD_NULL == (w->thd = ffthread_create((ffthread_proc)wrk_thread, w, 0))) {
		syserrlog("thread create");
		return -1;
	}
	return 0;
}

#ifdef FF_LINUX
typedef cpu_set_t _cpuset;
#elif defined FF_BSD
typedef cpuset_t _cpuset;
#endif

static void wrk_cpu_affinity(struct worker *w, uint icpu)
{
#ifdef FF_UNIX
	_cpuset cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(icpu, &cpuset);
	ffthread t = (w->thd != FFTHREAD_NULL) ? w->thd : pthread_self();
	if (0 != pthread_setaffinity_np(t, sizeof(cpuset), &cpuset)) {
		syserrlog("set CPU affinity");
		return;
	}
	dbglog("worker %p: CPU affinity: %u", w, icpu);
#endif
}

/** Send stop signal to all workers */
static void boss_stop()
{
	struct worker *w;
	FFSLICE_WALK(&boss->workers, w) {
		if (w->srv != NULL)
			nml_http_server_stop(w->srv);
	}
}

static void wrk_destroy(struct worker *w)
{
	if (w->srv == NULL) return;

	nml_http_server_stop(w->srv);
	if (w->thd != FFTHREAD_NULL) {
		ffthread_join(w->thd, -1, NULL);
	}
	nml_http_server_free(w->srv);
}

static void boss_destroy()
{
	if (boss == NULL)
		return;

	zzkcq_destroy(&boss->kcq);

	struct worker *w;
	FFSLICE_WALK(&boss->workers, w) {
		wrk_destroy(w);
	}
	ffvec_free(&boss->workers);
}

static void cpu_affinity()
{
	if (conf->cpumask == 0)
		return;

	uint mask = conf->cpumask;
	struct worker *w;
	FFSLICE_WALK(&boss->workers, w) {
		uint n = ffbit_rfind32(mask);
		if (n == 0)
			break;
		n--;
		ffbit_reset32(&mask, n);
		wrk_cpu_affinity(w, n);
	}
}

static void onsig(struct ffsig_info *i)
{
	boss_stop();
}

/** Initialize HTTP modules */
static void http_mods_init(struct nml_http_server_conf *aconf)
{
	ffvec v = {};
	char *fn = conf_abs_filename(conf, "content-types.conf");
	if (0 == fffile_readwhole(fn, &v, 64*1024)) {
		nml_http_file_init(aconf, *(ffstr*)&v);
		ffvec_null(&v);
	}
	ffvec_free(&v);
	ffmem_free(fn);
}

static void boss_log(void *opaque, uint level, const char *ctx, const char *id, const char *fmt, ...)
{
	struct boss *boss = opaque;
	va_list va;
	va_start(va, fmt);

	uint flags = level;
	if (level == NML_LOG_SYSFATAL
		|| level == NML_LOG_SYSERR
		|| level == NML_LOG_SYSWARN)
		flags |= ZZLOG_SYS_ERROR;

	zzlog_printv(&boss->log, flags, ctx, id, fmt, va);
	va_end(va);
}

static void aconf_setup()
{
	struct nml_http_server_conf *sc = &conf->aconf;
	sc->log_obj = boss;
	sc->log = boss_log;
	sc->log_date_buffer = boss->log.date;

	sc->server.conn_id_counter = &boss->conn_id;
	sc->server.reuse_port = 1;

	if (conf->kcall_workers != 0) {
		sc->kcq_sq = boss->kcq.sq;
		sc->kcq_sq_sem = boss->kcq.sem;
	}

	sc->filters = (void*)nml_http_server_filters;
	if (conf->proxy)
		sc->filters = (void*)nml_http_server_filters_proxy;

	http_mods_init(sc);
}

/** Check if fd is a terminal */
static int std_console(fffd fd)
{
#ifdef FF_WIN
	DWORD r;
	return GetConsoleMode(fd, &r);

#else
	fffileinfo fi;
	return (0 == fffile_info(fd, &fi)
		&& FFFILE_UNIX_CHAR == (fffileinfo_attr(&fi) & FFFILE_UNIX_TYPEMASK));
#endif
}

static void log_init(struct boss *boss)
{
	boss->log.fd = ffstdout;

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
	ffmem_copy(boss->log.levels, levels, sizeof(levels));

#ifdef FF_WIN
	boss->log.stdout_color = (0 == ffstd_attr(ffstdout, FFSTD_VTERM, FFSTD_VTERM));
	(void)std_console;
#else
	boss->log.stdout_color = std_console(ffstdout);
#endif
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
	ffmem_copy(boss->log.colors, colors, sizeof(colors));
}

int main(int argc, char **argv)
{
	static const char appname[] = "netmill v" NML_VERSION "\n";
	ffstdout_write(appname, FFS_LEN(appname));

	conf = ffmem_new(struct nml_http_sv_conf);
	conf_init(conf);
	if (0 != cmd_read(conf, argc, (const char**)argv))
		goto end;

#ifdef FF_UNIX
	if (conf->fd_limit != 0) {
		struct rlimit rl;
		rl.rlim_cur = conf->fd_limit;
		rl.rlim_max = conf->fd_limit;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
#endif

	boss = ffmem_new(struct boss);
	boss->conn_id = 1;

	log_init(boss);

	if (0 != ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		goto end;
	if (conf->kcall_workers != 0
		&& 0 != zzkcq_create(&boss->kcq, conf->kcall_workers, conf->aconf.server.max_connections, conf->aconf.server.polling_mode))
		goto end;

	aconf_setup();

	if (NULL == ffvec_zallocT(&boss->workers, conf->workers_n, struct worker))
		goto end;
	boss->workers.len = conf->workers_n;
	struct worker *w;
	FFSLICE_WALK(&boss->workers, w) {
		if (NULL == (w->srv = nml_http_server_new()))
			goto end;
		if (!!nml_http_server_conf(w->srv, &conf->aconf))
			goto end;
	}

	if (0 != zzkcq_start(&boss->kcq))
		goto end;

	FFSLICE_WALK(&boss->workers, w) {
		if (w != boss->workers.ptr) {
			if (0 != wrk_start(w))
				goto end;
		}
	}

	cpu_affinity();

	static const uint sigs[] = { FFSIG_INT };
	ffsig_subscribe(onsig, sigs, FF_COUNT(sigs));

	w = boss->workers.ptr;
	if (0 != nml_http_server_run(w->srv))
		goto end;

end:
	boss_destroy();
	ffmem_free(boss);
	conf_destroy(conf);
	ffmem_free(conf);
	return 0;
}
