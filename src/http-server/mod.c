/** netmill: http: start HTTP server
2022, Simon Zolin */

#include <netmill.h>
#include <util/ipaddr.h>
#include <ffsys/sysconf.h>
#include <ffsys/process.h>
#include <ffsys/path.h>
#include <ffsys/std.h>
#include <ffsys/thread.h>
#include <ffsys/globals.h>
#include <ffbase/args.h>
#include <util/kcq.h>
#include <util/util.h>

const nml_exe *exe;
extern const struct nml_http_client_if nml_http_client_interface;

#define syserrlog(...) \
	exe->log(NULL, NML_LOG_SYSERR, "http-server", NULL, __VA_ARGS__)

#define errlog(...) \
	exe->log(NULL, NML_LOG_ERR, "http-server", NULL, __VA_ARGS__)

#define dbglog(...) \
do { \
	if (exe->log_level >= NML_LOG_DEBUG) \
		exe->log(NULL, NML_LOG_DEBUG, "http-server", NULL, __VA_ARGS__); \
} while (0)

struct worker {
	nml_http_server *htsv;
	ffthread thd;
};

struct http_sv_conf {
	uint workers_n;
	uint cpumask;
	uint kcall_workers;
	ffbyte proxy;

	struct nml_address listen_addr[2];
	struct nml_http_server_conf sv;

	struct zzkcq kcq;
	ffvec workers; // struct worker[]
	uint conn_id;
};
static struct http_sv_conf *hc;

#define R_DONE  100
#define R_BADVAL  101

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

	return 0;
}

static int http_cmd_help()
{
	exe->print(
"Start HTTP server\n\
    `netmill http` [OPTIONS]\n\
\n\
Options:\n\
  `threads` N         Worker threads (def: CPU#)\n\
  `cpumask` N         CPU affinity bitmask, hex value (e.g. 15 for CPUs 0,2,4)\n\
  `kcall-threads` N   kcall worker threads (def: CPU#)\n\
  `polling`           Active polling mode\n\
\n\
  `listen` ADDR       Listening IP and TCP port (def: 80)\n\
                      e.g. 8080 or 127.0.0.1:8080 or [::1]:8080\n\
  `www` DIR           Web directory (def: www)\n\
  `proxy`             Act as a proxy (disable serving local files from 'www')\n\
");
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

/** Initialize HTTP modules */
static void http_mods_init(struct nml_http_server_conf *sv)
{
	ffvec v = {};
	char *fn = exe->path("content-types.conf");
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
	if (!(s = nml_http_server_create()))
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
	FFSLICE_WALK(&hc->workers, w) {
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
		&& 0 != zzkcq_create(&hc->kcq, hc->kcall_workers, hc->sv.server.max_connections, hc->sv.server.polling_mode))
		return -1;

	struct nml_http_server_conf *sc = &hc->sv;
	sc->log_level = exe->log_level;
	sc->log_obj = NULL;
	sc->log = exe->log;
	sc->log_date_buffer = exe->log_date_buffer;

	sc->server.conn_id_counter = &hc->conn_id;
	sc->server.reuse_port = 1;

	if (hc->kcall_workers != 0) {
		sc->kcq_sq = hc->kcq.sq;
		sc->kcq_sq_sem = hc->kcq.sem;
	}

	sc->chain = (void*)nml_http_server_chain;
	if (hc->proxy)
		sc->chain = (void*)nml_http_server_chain_proxy;

	http_mods_init(sc);

	if (!ffvec_zallocT(&hc->workers, hc->workers_n, struct worker))
		return -1;
	hc->workers.len = hc->workers_n;
	struct worker *w;
	FFSLICE_WALK(&hc->workers, w) {
		if (!(w->htsv = http_wrk_create()))
			return -1;
	}

	cpu_affinity();
	return 0;
}

/** Send stop signal to all workers */
static void http_stop()
{
	struct worker *w;
	FFSLICE_WALK(&hc->workers, w) {
		if (w->htsv)
			nml_http_server_stop(w->htsv);
	}
}

static void http_wrk_destroy(struct worker *w)
{
	if (w->htsv == NULL) return;

	nml_http_server_stop(w->htsv);
	if (w->thd != FFTHREAD_NULL) {
		ffthread_join(w->thd, -1, NULL);
	}
	nml_http_server_free(w->htsv);
}

static int FFTHREAD_PROCCALL http_wrk_thread(struct worker *w)
{
	dbglog("worker: started");
	return nml_http_server_run(w->htsv);
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
	if (zzkcq_start(&hc->kcq))
		return -1;

	struct worker *w;
	FFSLICE_WALK(&hc->workers, w) {
		if (w != hc->workers.ptr) {
			if (http_wrk_start(w))
				return -1;
		}
	}

	w = hc->workers.ptr;
	if (nml_http_server_run(w->htsv))
		return -1;
	return 0;
}


static nml_op* htsv_create(char **argv)
{
	hc = http_conf();

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, http_args, hc, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
		{}
		else if (r == R_BADVAL)
			errlog("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			errlog("command line: %s\n", as.error);
		return NULL;
	}

	hc->sv.server.wif = exe->provide("core.worker");
	hc->sv.server.lsif = exe->provide("core.tcp_listener");

#ifndef NML_HTTP_CLIENT_DISABLE
	hc->sv.hcif = &nml_http_client_interface;
	hc->sv.cif = exe->provide("core.cache");
#endif

	return hc;
}

static void htsv_close(nml_op *op)
{
	struct worker *w;
	FFSLICE_WALK(&hc->workers, w) {
		http_wrk_destroy(w);
	}

	nml_http_file_uninit(&hc->sv);
	zzkcq_destroy(&hc->kcq);
	ffvec_free(&hc->workers);
	ffmem_free(hc);
	hc = NULL;
}

static void htsv_run(nml_op *op)
{
	http_setup();
	http_run();
}

static void htsv_signal(nml_op *op, uint signal)
{
	http_stop();
}

static const struct nml_operation_if nml_op_http_sv = {
	htsv_create,
	htsv_close,
	htsv_run,
	htsv_signal,
};


static void htsv_init(const nml_exe *x)
{
	exe = x;
}

static void htsv_destroy()
{
}

extern const struct nml_operation_if nml_op_url;

extern const nml_http_cl_component
	nml_http_cl_resolve,
	nml_http_cl_connection_cache,
	nml_http_cl_connect,
	nml_http_cl_io,
	nml_http_cl_send,
	nml_http_cl_recv,
	nml_http_cl_response,
	nml_http_cl_request,
	nml_http_cl_transfer,
	nml_http_cl_redir;

static const void* htsv_provide(const char *name)
{
	static const struct nml_if_map map[] = {
#ifndef NML_HTTP_CLIENT_DISABLE
		{"cl_conn_cache_destroy",nml_http_cl_conn_cache_destroy},
		{"cl_connect",			&nml_http_cl_connect},
		{"cl_connection_cache",	&nml_http_cl_connection_cache},
		{"cl_io",				&nml_http_cl_io},
		{"cl_recv",				&nml_http_cl_recv},
		{"cl_request",			&nml_http_cl_request},
		{"cl_resolve",			&nml_http_cl_resolve},
		{"cl_response",			&nml_http_cl_response},
		{"cl_send",				&nml_http_cl_send},
		{"cl_transfer",			&nml_http_cl_transfer},
		{"client",				&nml_http_client_interface},
#endif
		{"http",				&nml_op_http_sv},
		{"url",					&nml_op_url},
		// nml_http_cl_redir
	};
	return nml_if_map_find(map, FF_COUNT(map), name);
}

NML_MOD_DEFINE(htsv);
