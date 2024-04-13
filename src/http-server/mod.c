/** netmill: http: start HTTP server
2022, Simon Zolin */

#include <netmill.h>
#include <util/ipaddr.h>
#include <util/kcq.h>
#include <util/util.h>
#include <util/ssl.h>
#include <ffsys/sysconf.h>
#include <ffsys/process.h>
#include <ffsys/path.h>
#include <ffsys/std.h>
#include <ffsys/thread.h>
#include <ffsys/globals.h>
#include <ffbase/args.h>

const nml_exe *exe;
extern const struct nml_http_client_if nml_http_client_interface;

#define SV_SYSERR(...) \
	exe->log(NULL, NML_LOG_SYSERR, "http-server", NULL, __VA_ARGS__)

#define SV_ERR(...) \
	exe->log(NULL, NML_LOG_ERR, "http-server", NULL, __VA_ARGS__)

#define SV_DEBUG(...) \
do { \
	if (exe->log_level >= NML_LOG_DEBUG) \
		exe->log(NULL, NML_LOG_DEBUG, "http-server", NULL, __VA_ARGS__); \
} while (0)

struct worker {
	nml_http_server *htsv;
	ffthread thd;
};

struct http_sv_exe {
	uint workers_n;
	uint cpumask;
	uint kcall_workers;
	u_char proxy;

	char*	cert_key_file;

	struct nml_address listen_addr[2];
	struct nml_http_server_conf hsc;

	struct zzkcq kcq;
	ffvec workers; // struct worker[]
	uint conn_id;
};

#define R_DONE  100
#define R_BADVAL  101

static int http_cmd_listen(struct http_sv_exe *conf, ffstr val)
{
	if (0 > ffip_port_split(val, conf->listen_addr[0].ip, &conf->listen_addr[0].port))
		return R_BADVAL;
	conf->hsc.server.listen_addresses = conf->listen_addr;
	return 0;
}

static int http_cmd_cpumask(struct http_sv_exe *conf, ffstr val)
{
	if (!ffstr_toint(&val, &conf->cpumask, FFS_INT32 | FFS_INTHEX))
		return R_BADVAL;
	return 0;
}

static int http_cmd_fin(struct http_sv_exe *conf)
{
	if (!(conf->hsc.receive.buf_size > 16 && conf->hsc.response.buf_size > 16)) {
		ffstderr_fmt("bad buffer sizes\n");
		return -1;
	}

	if (!conf->workers_n
		|| conf->kcall_workers == ~0) {

		ffsysconf sc;
		ffsysconf_init(&sc);
		uint cpu_n = ffsysconf_get(&sc, FFSYSCONF_NPROCESSORS_ONLN);

		if (!conf->workers_n) {
			conf->workers_n = cpu_n;
#ifdef FF_WIN
			conf->workers_n = 1;
#endif
			if (!conf->cpumask)
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
\n\
SSL:\n\
  `cert` FILE         Set certificate & private-key PEM file\n\
\n\
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

#define O(m)  (void*)(size_t)FF_OFF(struct http_sv_exe, m)
static const struct ffarg http_args[] = {
	{ "cert",			'=s',	O(cert_key_file) },
	{ "cpumask",		'S',	http_cmd_cpumask },
	{ "help",			'1',	http_cmd_help },
	{ "kcall-threads",	'u',	O(kcall_workers) },
	{ "listen",			'S',	http_cmd_listen },
	{ "polling",		'1',	O(hsc.server.polling_mode) },
#ifndef NML_HTTP_CLIENT_DISABLE
	{ "proxy",			'1',	O(proxy) },
#endif
	{ "threads",		'u',	O(workers_n) },
	{ "www",			'S',	O(hsc.fs.www) },
	{ "",				'1',	http_cmd_fin },
	{}
};
#undef O

static struct http_sv_exe* http_conf()
{
	struct http_sv_exe *conf = ffmem_new(struct http_sv_exe);
	conf->listen_addr[0].port = 8080;
	nml_http_server_conf(NULL, &conf->hsc);
	ffstr_setz(&conf->hsc.fs.www, "www");
	conf->kcall_workers = ~0;
	return conf;
}

/** Initialize HTTP modules */
static void http_mods_init(struct nml_http_server_conf *hsc)
{
	ffvec v = {};
	char *fn = exe->path("content-types.conf");
	if (!fffile_readwhole(fn, &v, 64*1024)) {
		nml_http_file_init(hsc, *(ffstr*)&v);
		ffvec_null(&v);
	}
	ffvec_free(&v);
	ffmem_free(fn);
}

static nml_http_server* http_wrk_create(struct http_sv_exe *sx)
{
	nml_http_server *s;
	if (!(s = nml_http_server_create()))
		return NULL;
	if (nml_http_server_conf(s, &sx->hsc)) {
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
		SV_SYSERR("set CPU affinity");
		return;
	}
	SV_DEBUG("worker %p: CPU affinity: %u", w, icpu);
#endif
}

static void http_cpu_affinity(struct http_sv_exe *sx)
{
	if (!sx->cpumask) return;

	uint mask = sx->cpumask;
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		uint n = ffbit_rfind32(mask);
		if (!n)
			break;
		n--;
		ffbit_reset32(&mask, n);
		wrk_cpu_affinity(w, n);
	}
}

static nml_cache_ctx* htsv_proxy_conn_cache(struct http_sv_exe *sx)
{
	struct nml_cache_conf *cc = ffmem_new(struct nml_cache_conf);
	sx->hsc.cif->conf(NULL, cc);

	cc->log_level = exe->log_level;
	cc->log = exe->log;
	cc->log_obj = NULL;

	cc->max_items = 60000;
	cc->destroy = exe->provide("http.cl_conn_cache_destroy");
	cc->opaque = NULL;

	nml_cache_ctx *cx = sx->hsc.cif->create();
	if (!cx)
		return NULL;
	sx->hsc.cif->conf(cx, cc);
	return cx;
}

extern const nml_http_sv_component** nml_http_sv_chain(const nml_exe *exe, uint ssl);
extern const nml_component* nml_http_server_chain_proxy[];

static int ssl_prepare(struct http_sv_exe *sx)
{
	if (!(sx->hsc.slif = exe->provide("ssl.ssl")))
		return -1;

	struct nml_ssl_ctx *sc = ffmem_new(struct nml_ssl_ctx);
	sx->hsc.ssl_ctx = sc;
	struct ffssl_ctx_conf *scc = ffmem_new(struct ffssl_ctx_conf);
	sc->ctx_conf = scc;

	scc->cert_file = sx->cert_key_file;
	scc->pkey_file = sx->cert_key_file;
	// scc->allowed_protocols = FFSSL_PROTO_TLS13;

	sc->log_level = exe->log_level;
	sc->log_obj = NULL;
	sc->log = exe->log;

	if (sx->hsc.slif->init(sc))
		return -1;

	sx->hsc.chain = nml_http_sv_chain(exe, 1);
	return 0;
}

static int http_setup(struct http_sv_exe *sx)
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	if (sx->kcall_workers
		&& zzkcq_create(&sx->kcq, sx->kcall_workers, sx->hsc.server.max_connections, sx->hsc.server.polling_mode))
		return -1;

	struct nml_http_server_conf *hsc = &sx->hsc;
	hsc->log_level = exe->log_level;
	hsc->log_obj = NULL;
	hsc->log = exe->log;
	hsc->log_date_buffer = exe->log_date_buffer;

	hsc->server.conn_id_counter = &sx->conn_id;
	hsc->server.reuse_port = 1;

	if (sx->kcall_workers) {
		hsc->kcq_sq = sx->kcq.sq;
		hsc->kcq_sq_sem = sx->kcq.sem;
	}

	if (!sx->proxy) {
		if (sx->cert_key_file) {
			if (ssl_prepare(sx))
				return -1;
		} else {
			hsc->chain = nml_http_sv_chain(exe, 0);
		}
	}

#ifndef NML_HTTP_CLIENT_DISABLE
	if (sx->proxy) {
		hsc->connection_cache = htsv_proxy_conn_cache(sx);
		hsc->chain = (void*)nml_http_server_chain_proxy;
	}
#endif

	http_mods_init(hsc);

	if (NULL == ffvec_zallocT(&sx->workers, sx->workers_n, struct worker))
		return -1;
	sx->workers.len = sx->workers_n;
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		if (!(w->htsv = http_wrk_create(sx)))
			return -1;
	}

	http_cpu_affinity(sx);
	return 0;
}

/** Send stop signal to all workers */
static void http_stop(struct http_sv_exe *sx)
{
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		if (w->htsv)
			nml_http_server_stop(w->htsv);
	}
}

static void http_wrk_destroy(struct worker *w)
{
	if (!w->htsv) return;

	nml_http_server_stop(w->htsv);
	if (w->thd != FFTHREAD_NULL) {
		ffthread_join(w->thd, -1, NULL);
	}
	nml_http_server_free(w->htsv);
}

static int FFTHREAD_PROCCALL http_wrk_thread(struct worker *w)
{
	SV_DEBUG("worker: started");
	return nml_http_server_run(w->htsv);
}

static int http_wrk_start(struct worker *w)
{
	if (FFTHREAD_NULL == (w->thd = ffthread_create((ffthread_proc)http_wrk_thread, w, 0))) {
		SV_SYSERR("thread create");
		return -1;
	}
	return 0;
}

static int http_run(struct http_sv_exe *sx)
{
	if (zzkcq_start(&sx->kcq))
		return -1;

	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		if (w != sx->workers.ptr) {
			if (http_wrk_start(w))
				return -1;
		}
	}

	w = sx->workers.ptr;
	if (nml_http_server_run(w->htsv))
		return -1;
	return 0;
}


static nml_op* htsv_create(char **argv)
{
	struct http_sv_exe *sx = http_conf();

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, http_args, sx, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
			exe->exit(0);
		else if (r == R_BADVAL)
			SV_ERR("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			SV_ERR("command line: %s\n", as.error);
		return NULL;
	}

	sx->hsc.server.wif = exe->provide("core.worker");
	sx->hsc.server.lsif = exe->provide("core.tcp_listener");

#ifndef NML_HTTP_CLIENT_DISABLE
	sx->hsc.hcif = &nml_http_client_interface;
	sx->hsc.cif = exe->provide("core.cache");
#endif

	return sx;
}

static void htsv_close(nml_op *op)
{
	struct http_sv_exe *sx = op;
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		http_wrk_destroy(w);
	}

	nml_http_file_uninit(&sx->hsc);
	zzkcq_destroy(&sx->kcq);
	ffvec_free(&sx->workers);
	ffmem_free(sx);
}

static void htsv_run(nml_op *op)
{
	struct http_sv_exe *sx = op;
	if (http_setup(sx))
		return;
	http_run(sx);
}

static void htsv_signal(nml_op *op, uint signal)
{
	struct http_sv_exe *sx = op;
	http_stop(sx);
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
