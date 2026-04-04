/** netmill: start SOCKS server
2026, Simon Zolin */

#include <netmill-socks.h>
#include <util/ipaddr.h>
#include <util/kcq.h>
#include <util/util.h>
#include <ffsys/sysconf.h>
#include <ffsys/process.h>
#include <ffsys/path.h>
#include <ffsys/std.h>
#include <ffsys/thread.h>
#include <ffsys/globals.h>
#include <ffbase/args.h>

const nml_exe *exe;

#define SKSV_SYSERR(...) \
	exe->log(NULL, NML_LOG_SYSERR, "socks-server", NULL, __VA_ARGS__)

#define SKSV_ERR(...) \
	exe->log(NULL, NML_LOG_ERR, "socks-server", NULL, __VA_ARGS__)

#define SKSV_DEBUG(...) \
do { \
	if (exe->log_level >= NML_LOG_DEBUG) \
		exe->log(NULL, NML_LOG_DEBUG, "socks-server", NULL, __VA_ARGS__); \
} while (0)

struct worker {
	nml_socks_server *sksv;
	ffthread thd;
};

struct socks_sv_exe {
	u_char allow;
	uint workers_n;
	uint cpumask;

	struct nml_address listen_addr[2];
	struct nml_socks_server_conf ssc;

	struct zzkcq kcq;
	ffvec workers; // struct worker[]
	uint conn_id;
};

#define R_DONE  100
#define R_BADVAL  101

static int socks_cmd_listen(struct socks_sv_exe *conf, ffstr val)
{
	if (0 > ffip_port_split(val, conf->listen_addr[0].ip, &conf->listen_addr[0].port))
		return R_BADVAL;
	conf->ssc.server.listen_addresses = conf->listen_addr;
	return 0;
}

static int socks_cmd_cpumask(struct socks_sv_exe *conf, ffstr val)
{
	if (!ffstr_toint(&val, &conf->cpumask, FFS_INT32 | FFS_INTHEX))
		return R_BADVAL;
	return 0;
}

static int socks_cmd_fin(struct socks_sv_exe *conf)
{
	if (!conf->workers_n) {

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
	}

	return 0;
}

static int socks_cmd_help()
{
	exe->print(
"Start SOCKS server\n\
    `netmill socks` [OPTIONS]\n\
\n\
Options:\n\
\n\
  `threads` N         Worker threads (def: CPU#)\n\
  `cpumask` N         CPU affinity bitmask, hex value (e.g. 15 for CPUs 0,2,4)\n\
  `kcall-threads` N   kcall worker threads (def: CPU#)\n\
\n\
  `listen` ADDR       Listening IP and TCP port (def: 1080)\n\
                      e.g. 1080 or 127.0.0.1:1080 or [::1]:1080\n\
\n\
  `allow`             Allow all target hosts\n\
");
	return R_DONE;
}

#define O(m)  (void*)(size_t)FF_OFF(struct socks_sv_exe, m)
static const struct ffarg socks_args[] = {
	{ "allow",			'1',	O(allow) },
	{ "cpumask",		'S',	socks_cmd_cpumask },
	{ "help",			'1',	socks_cmd_help },
	{ "listen",			'S',	socks_cmd_listen },
	{ "threads",		'u',	O(workers_n) },
	{ "",				'1',	socks_cmd_fin },
	{}
};
#undef O

static struct socks_sv_exe* socks_conf()
{
	struct socks_sv_exe *conf = ffmem_new(struct socks_sv_exe);
	conf->listen_addr[0].port = 1080;
	nml_socks_server_conf(NULL, &conf->ssc);
	return conf;
}

static nml_socks_server* socks_wrk_create(struct socks_sv_exe *sx)
{
	nml_socks_server *s;
	if (!(s = nml_socks_server_create()))
		return NULL;
	if (nml_socks_server_conf(s, &sx->ssc)) {
		nml_socks_server_free(s);
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
		SKSV_SYSERR("set CPU affinity");
		return;
	}
	SKSV_DEBUG("worker %p: CPU affinity: %u", w, icpu);
#endif
}

static void socks_cpu_affinity(struct socks_sv_exe *sx)
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

extern const nml_socks_sv_component* nml_socks_server_chain[];

static int sksv_setup(struct socks_sv_exe *sx)
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	struct nml_socks_server_conf *ssc = &sx->ssc;
	ssc->log_level = exe->log_level;
	ssc->log_obj = NULL;
	ssc->log = exe->log;
	ssc->log_date_buffer = exe->log_date_buffer;

	ssc->server.conn_id_counter = &sx->conn_id;
	ssc->server.reuse_port = 1;

	ssc->chain = nml_socks_server_chain;

	ssc->allow_all_targets = sx->allow;

	if (!ffvec_zallocT(&sx->workers, sx->workers_n, struct worker))
		return -1;
	sx->workers.len = sx->workers_n;
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		if (!(w->sksv = socks_wrk_create(sx)))
			return -1;
	}

	socks_cpu_affinity(sx);
	return 0;
}

/** Send stop signal to all workers */
static void sksv_stop(struct socks_sv_exe *sx)
{
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		if (w->sksv)
			nml_socks_server_stop(w->sksv);
	}
}

static void socks_wrk_destroy(struct worker *w)
{
	if (!w->sksv) return;

	nml_socks_server_stop(w->sksv);
	if (w->thd != FFTHREAD_NULL) {
		ffthread_join(w->thd, -1, NULL);
	}
	nml_socks_server_free(w->sksv);
}

static int FFTHREAD_PROCCALL socks_wrk_thread(struct worker *w)
{
	SKSV_DEBUG("worker: started");
	return nml_socks_server_run(w->sksv);
}

static int socks_wrk_start(struct worker *w)
{
	if (FFTHREAD_NULL == (w->thd = ffthread_create((ffthread_proc)socks_wrk_thread, w, 0))) {
		SKSV_SYSERR("thread create");
		return -1;
	}
	return 0;
}

static int socks_run(struct socks_sv_exe *sx)
{
	if (zzkcq_start(&sx->kcq, -1))
		return -1;

	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		if (w != sx->workers.ptr) {
			if (socks_wrk_start(w))
				return -1;
		}
	}

	w = sx->workers.ptr;
	if (nml_socks_server_run(w->sksv))
		return -1;
	return 0;
}


static nml_op* sksv_create(char **argv)
{
	struct socks_sv_exe *sx = socks_conf();

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, socks_args, sx, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
			exe->exit(0);
		else if (r == R_BADVAL)
			SKSV_ERR("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			SKSV_ERR("command line: %s\n", as.error);
		return NULL;
	}

	sx->ssc.server.wif = exe->provide("core.worker");
	sx->ssc.server.lsif = exe->provide("core.tcp_listener");
	return sx;
}

static void sksv_close(nml_op *op)
{
	struct socks_sv_exe *sx = op;
	struct worker *w;
	FFSLICE_WALK(&sx->workers, w) {
		socks_wrk_destroy(w);
	}

	zzkcq_destroy(&sx->kcq);
	ffvec_free(&sx->workers);
	ffmem_free(sx);
}

static void sksv_run(nml_op *op)
{
	struct socks_sv_exe *sx = op;
	if (sksv_setup(sx))
		return;
	socks_run(sx);
}

static void sksv_signal(nml_op *op, uint signal)
{
	struct socks_sv_exe *sx = op;
	sksv_stop(sx);
}

static const struct nml_operation_if nml_op_socks_sv = {
	sksv_create,
	sksv_close,
	sksv_run,
	sksv_signal,
};


static void sksv_init(const nml_exe *x)
{
	exe = x;
}

static void sksv_destroy()
{
}

extern const struct nml_operation_if nml_op_request;

static const void* sksv_provide(const char *name)
{
	static const struct nml_if_map map[] = {
		{"server",				&nml_op_socks_sv},
	};
	return nml_if_map_find(map, FF_COUNT(map), name);
}

NML_MOD_DEFINE(sksv);
