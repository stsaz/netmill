/** netmill: executor: start HTTP server
2022, Simon Zolin */

#include <exe/shared.h>
#include <util/ipaddr.h>
#include <ffsys/sysconf.h>
#include <ffsys/process.h>
#include <ffsys/path.h>
#include <ffsys/std.h>
#include <ffbase/args.h>

struct http_sv_conf {
	uint workers_n;
	uint cpumask;
	uint kcall_workers;
	ffbyte proxy;

	struct nml_address listen_addr[2];
	struct nml_http_server_conf sv;
};
static struct http_sv_conf *hc;

static int http_cmd_listen(struct http_sv_conf *conf, ffstr val)
{
	if (0 > ffip_port_split(val, conf->listen_addr[0].ip, &conf->listen_addr[0].port))
		return R_BADVAL;
	conf->sv.server.listen_addresses = conf->listen_addr;
	return 0;
}

static int http_cmd_cpumask(struct http_sv_conf *conf, ffstr val)
{
	if (!ffstr_toint(&val, &conf->cpumask, FFS_INT32 | FFS_INTHEX))
		return R_BADVAL;
	return 0;
}

static const job_if http_serv;

static int http_cmd_fin(struct http_sv_conf *conf)
{
	if (!(conf->sv.receive.buf_size > 16 && conf->sv.response.buf_size > 16)) {
		ffstderr_fmt("bad buffer sizes\n");
		return -1;
	}

	if (conf->workers_n == 0
		|| conf->kcall_workers == ~0) {

		ffsysconf sc;
		ffsysconf_init(&sc);
		uint cpu_n = ffsysconf_get(&sc, FFSYSCONF_NPROCESSORS_ONLN);

		if (conf->workers_n == 0) {
			conf->workers_n = cpu_n;
#ifdef FF_WIN
			conf->workers_n = 1;
#endif
			if (conf->cpumask == 0)
				conf->cpumask = ~0;
		}

		if (conf->kcall_workers == ~0)
			conf->kcall_workers = cpu_n;
	}

	x->job = &http_serv;
	return 0;
}

static int http_cmd_help()
{
	static const char help[] =
"Start HTTP server\n\
    netmill http [OPTIONS]\n\
\n\
Options:\n\
  threads N         Worker threads (def: CPU#)\n\
  cpumask N         CPU affinity bitmask, hex value (e.g. 15 for CPUs 0,2,4)\n\
  kcall-threads N   kcall worker threads (def: CPU#)\n\
  polling           Active polling mode\n\
\n\
  listen ADDR       Listening IP and TCP port (def: 80)\n\
                      e.g. 8080 or 127.0.0.1:8080 or [::1]:8080\n\
  www DIR           Web directory (def: www)\n\
  proxy             Act as a proxy (disable serving local files from 'www')\n\
";
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct http_sv_conf, m)
static const struct ffarg http_args[] = {
	{ "cpumask",		'S',	http_cmd_cpumask },
	{ "help",			'1',	http_cmd_help },
	{ "kcall-threads",	'u',	O(kcall_workers) },
	{ "listen",			'S',	http_cmd_listen },
	{ "polling",		'1',	O(sv.server.polling_mode) },
	{ "proxy",			'1',	O(proxy) },
	{ "threads",		'u',	O(workers_n) },
	{ "www",			'S',	O(sv.fs.www) },
	{ "",				'1',	http_cmd_fin },
	{}
};
#undef O

static struct http_sv_conf* http_conf()
{
	struct http_sv_conf *conf = ffmem_new(struct http_sv_conf);
	conf->listen_addr[0].port = 8080;
	nml_http_server_conf(NULL, &conf->sv);
	ffstr_setz(&conf->sv.fs.www, "www");
	conf->kcall_workers = ~0;
	return conf;
}

struct ffarg_ctx http_ctx()
{
	hc = http_conf();
	struct ffarg_ctx ax = { http_args, hc };
	return ax;
}

/** Initialize HTTP modules */
static void http_mods_init(struct nml_http_server_conf *sv)
{
	ffvec v = {};
	char *fn = conf_abs_filename("content-types.conf");
	if (!fffile_readwhole(fn, &v, 64*1024)) {
		nml_http_file_init(sv, *(ffstr*)&v);
		ffvec_null(&v);
	}
	ffvec_free(&v);
	ffmem_free(fn);
}

static void* http_wrk_create()
{
	nml_http_server *s;
	if (!(s = nml_http_server_new()))
		return NULL;
	if (nml_http_server_conf(s, &hc->sv)) {
		nml_http_server_free(s);
		return NULL;
	}
	return s;
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
	if (pthread_setaffinity_np(t, sizeof(cpuset), &cpuset)) {
		syserrlog("set CPU affinity");
		return;
	}
	dbglog("worker %p: CPU affinity: %u", w, icpu);
#endif
}

static void cpu_affinity()
{
	if (hc->cpumask == 0) return;

	uint mask = hc->cpumask;
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		uint n = ffbit_rfind32(mask);
		if (n == 0)
			break;
		n--;
		ffbit_reset32(&mask, n);
		wrk_cpu_affinity(w, n);
	}
}

extern const nml_component* nml_http_server_chain[];
extern const nml_component* nml_http_server_chain_proxy[];

static int http_setup()
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	if (hc->kcall_workers != 0
		&& 0 != zzkcq_create(&x->kcq, hc->kcall_workers, hc->sv.server.max_connections, hc->sv.server.polling_mode))
		return -1;

	struct nml_http_server_conf *sc = &hc->sv;
	sc->log_level = x->conf.log_level;
	sc->log_obj = x;
	sc->log = exe_log;
	sc->log_date_buffer = x->log.date;

	sc->server.conn_id_counter = &x->conn_id;
	sc->server.reuse_port = 1;

	if (hc->kcall_workers != 0) {
		sc->kcq_sq = x->kcq.sq;
		sc->kcq_sq_sem = x->kcq.sem;
	}

	sc->chain = (void*)nml_http_server_chain;
	if (hc->proxy)
		sc->chain = (void*)nml_http_server_chain_proxy;

	http_mods_init(sc);

	if (NULL == ffvec_zallocT(&x->workers, hc->workers_n, struct worker))
		return -1;
	x->workers.len = hc->workers_n;
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (NULL == (w->http = http_wrk_create()))
			return -1;
	}

	cpu_affinity();
	return 0;
}

/** Send stop signal to all workers */
static void http_stop()
{
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (w->http)
			nml_http_server_stop(w->http);
	}
}

static void http_wrk_destroy(struct worker *w)
{
	if (w->http == NULL) return;

	nml_http_server_stop(w->http);
	if (w->thd != FFTHREAD_NULL) {
		ffthread_join(w->thd, -1, NULL);
	}
	nml_http_server_free(w->http);
}

static void http_destroy()
{
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		http_wrk_destroy(w);
	}

	nml_http_file_uninit(&hc->sv);
}

static int FFTHREAD_PROCCALL http_wrk_thread(struct worker *w)
{
	dbglog("worker: started");
	return nml_http_server_run(w->http);
}

static int http_wrk_start(struct worker *w)
{
	if (FFTHREAD_NULL == (w->thd = ffthread_create((ffthread_proc)http_wrk_thread, w, 0))) {
		syserrlog("thread create");
		return -1;
	}
	return 0;
}

static int http_run()
{
	if (zzkcq_start(&x->kcq))
		return -1;

	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (w != x->workers.ptr) {
			if (http_wrk_start(w))
				return -1;
		}
	}

	w = x->workers.ptr;
	if (nml_http_server_run(w->http))
		return -1;
	return 0;
}

static const job_if http_serv = {
	.setup = http_setup,
	.run = http_run,
	.stop = http_stop,
	.destroy = http_destroy,
};
