/** netmill: executor
2022, Simon Zolin */

#include <netmill.h>
#include <util/log.h>
#include <ffsys/signal.h>
#include <ffsys/thread.h>
#include <ffsys/process.h>
#include <ffsys/path.h>
#include <ffsys/dylib.h>
#include <ffsys/globals.h>
#include <ffbase/args.h>
#ifdef FF_UNIX
#include <sys/resource.h>
#endif

struct svc_conf;
struct exe_conf {
	uint log_level;
	ffstr root_dir;
	uint fd_limit;
	const char *log_fn;
	struct svc_conf *svc;
};

struct mod {
	char *name;
	ffdl dl;
	const nml_module *mif;
};

struct exe {
	int exit_code;
	struct exe_conf conf;
	struct zzlog log;

	fflock mods_lock;
	ffvec mods; // struct mod[]

	uint argi;
	const nml_operation_if *opif;
	void *op;
};

static struct exe *x;
static struct nml_exe exe_if;

#define X_SYSERR(...) \
	exe_log(NULL, NML_LOG_SYSERR, "exe", NULL, __VA_ARGS__)

#define X_ERR(...) \
	exe_log(NULL, NML_LOG_ERR, "exe", NULL, __VA_ARGS__)

#define X_INFO(...) \
	exe_log(NULL, NML_LOG_INFO, "exe", NULL, __VA_ARGS__)

#define X_DEBUG(...) \
do { \
	if (x->conf.log_level >= NML_LOG_DEBUG) \
		exe_log(NULL, NML_LOG_DEBUG, "exe", NULL, __VA_ARGS__); \
} while (0)

/** Convert relative file name to absolute file name using application directory */
static char* conf_abs_filename(const char *rel_fn)
{
	if (ffpath_abs(rel_fn, ffsz_len(rel_fn)))
		return ffsz_dup(rel_fn);
	return ffsz_allocfmt("%S%s", &x->conf.root_dir, rel_fn);
}

static void help_info_write(const char *sz)
{
	ffstr s = FFSTR_INITZ(sz), l, k;
	ffvec v = {};

	const char *clr = FFSTD_CLR_B(FFSTD_PURPLE);
	while (s.len) {
		ffstr_splitby(&s, '`', &l, &s);
		ffstr_splitby(&s, '`', &k, &s);
		if (x->log.use_color) {
			ffvec_addfmt(&v, "%S%s%S%s"
				, &l, clr, &k, FFSTD_CLR_RESET);
		} else {
			ffvec_addfmt(&v, "%S%S"
				, &l, &k);
		}
	}

	ffstdout_write(v.ptr, v.len);
	ffvec_free(&v);
}

#define R_DONE  100
#define R_BADVAL  101

#include <exe/log.h>
#include <exe/service.h>

static int cmd_debug(struct exe_conf *conf)
{
	conf->log_level = NML_LOG_DEBUG;
#ifdef NML_ENABLE_LOG_EXTRA
	conf->log_level = NML_LOG_EXTRA;
#endif
	return 0;
}

static int usage()
{
	help_info_write(
"Usage:\n\
    netmill [GLOBAL-OPTIONS] COMMAND [OPTIONS]\n\
\n\
Global options:\n\
  `-help`             Show help\n\
  `-Debug`            Print debug logs\n\
  `-log` FILE         Print logs to file\n\
\n\
Command:\n\
  `cert`          Generate certificate+key PEM file\n\
  `dns`           Start DNS server\n\
  `firewall`      Ingress firewall\n\
  `http`          Start HTTP server\n\
  `if`            Show network interfaces\n\
  `ping`          XDP ping\n\
  `service`       Install system service\n\
  `url`           Execute HTTP request\n\
\n\
\"netmill COMMAND help\" will print details on each command.\n\
");
	return R_DONE;
}

#define O(m)  (void*)(size_t)FF_OFF(struct exe_conf, m)
static const struct ffarg nml_args[] = {
	{ "-Debug",		'1',	cmd_debug },

	{ "-help",		'1',	usage },
	{ "-log",		's',	O(log_fn) },
	{ "service",	'{',	svc_ctx },
	{}
};
#undef O

static int conf_root_dir(struct exe_conf *conf, const char *argv0)
{
	char fn[4096];
	const char *p;
	if (NULL == (p = ffps_filename(fn, sizeof(fn), argv0)))
		return -1;
	ffstr path;
	if (0 > ffpath_splitpath(p, ffsz_len(p), &path, NULL))
		return -1;
	if (NULL == ffstr_dup(&conf->root_dir, path.ptr, path.len + 1))
		return -1;
	return 0;
}

static int cmd(struct exe_conf *conf, int argc, char **argv)
{
	conf->fd_limit = 10000 * 2;
#ifdef FF_UNIX
	if (conf->fd_limit != 0) {
		struct rlimit rl;
		rl.rlim_cur = conf->fd_limit;
		rl.rlim_max = conf->fd_limit;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
#endif

	if (conf_root_dir(conf, argv[0]))
		return -1;

	struct ffargs as = {};
	uint f = FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES | FFARGS_O_SKIP_FIRST;
	int r = ffargs_process_argv(&as, nml_args, conf, f, argv, argc);
	switch (r) {
	case 0:
		break;

	case R_DONE:
		x->exit_code = 0; break;

	case R_BADVAL:
		ffstderr_fmt("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		break;

	case -FFARGS_E_ARG:
		// we met the first operation-specific argument
		x->argi = as.argi - 1;
		return 0;

	default:
		ffstderr_fmt("command line: %s\n", as.error);
	}

	return -1;
}

static struct exe* init()
{
	static const char appname[] = "netmill v" NML_VERSION "\n";
	ffstdout_write(appname, FFS_LEN(appname));

	struct exe *c = ffmem_new(struct exe);
	return c;
}

static void onsig(struct ffsig_info *i)
{
	x->opif->signal(x->op, 0);
}

static int sigs()
{
	static const uint sigs[] = { FFSIG_INT };
	return ffsig_subscribe(onsig, sigs, FF_COUNT(sigs));
}

/** Find module */
static struct mod* mod_find(ffstr name)
{
	struct mod *m;
	FFSLICE_WALK(&x->mods, m) {
		if (ffstr_eqz(&name, m->name))
			return m;
	}
	return NULL;
}

static void mod_destroy(struct mod *m)
{
	if (!m) return;

	if (m->mif && m->mif->close) {
		X_DEBUG("'%s': closing module", m->name);
		m->mif->close();
	}
	if (m->dl != FFDL_NULL) {
		X_DEBUG("'%s': ffdl_close", m->name);
		ffdl_close(m->dl);
	}
	ffmem_free(m->name);
}

/** Create module object */
static struct mod* mod_create(ffstr name)
{
	struct mod *m = ffvec_zpushT(&x->mods, struct mod);
	m->name = ffsz_dupstr(&name);
	return m;
}

static ffdl mod_load(struct mod *m, ffstr file)
{
	int done = 0;
	ffdl dl = FFDL_NULL;

	char *fn = ffsz_allocfmt("%Sops%c%S.%s"
		, &x->conf.root_dir, FFPATH_SLASH, &file, FFDL_EXT);

	if (FFDL_NULL == (dl = ffdl_open(fn, FFDL_SELFDIR))) {
		X_ERR("%s: ffdl_open: %s", fn, ffdl_errstr());
		goto end;
	}

	if (!(m->mif = ffdl_addr(dl, "netmill_module"))) {
		X_ERR("%s: ffdl_addr '%s': %s"
			, fn, "netmill_module", ffdl_errstr());
		goto end;
	}

	X_DEBUG("loaded module %S v%s"
		, &file, m->mif->version);

	if (m->mif->ver_core != NML_CORE_VER) {
		X_ERR("module %S is incompatible with this netmill version", &file);
		goto end;
	}

	m->mif->init(&exe_if);

	done = 1;

end:
	ffmem_free(fn);
	if (!done && dl != FFDL_NULL)
		ffdl_close(dl);
	return dl;
}

extern struct nml_module netmill_module;

/** Load module, get interface */
static const void* exe_provide(const char *name)
{
	const void *p = NULL;
	int locked = 0;

	ffstr s = FFSTR_INITZ(name), file, iface;
	ffstr_splitby(&s, '.', &file, &iface);
	if (!file.len)
		goto end;

	if (ffstr_eqz(&file, "core")) {
		if (!(p = netmill_module.provide(iface.ptr))) {
			X_ERR("no such interface: '%s'", name);
			goto end;
		}
		return p;
	}

	fflock_lock(&x->mods_lock);
	locked = 1;
	struct mod *m = NULL;
	if (!(m = mod_find(file)))
		m = mod_create(file);

	if (m->dl == FFDL_NULL) {
		if (FFDL_NULL == (m->dl = mod_load(m, file)))
			goto end;
	}
	fflock_unlock(&x->mods_lock);
	locked = 0;

	if (!iface.len)
		goto end;

	if (!(p = m->mif->provide(iface.ptr))) {
		X_ERR("no such interface: '%s'", name);
		goto end;
	}

end:
	if (locked)
		fflock_unlock(&x->mods_lock);

	if (p)
		X_DEBUG("provide: %s", name);
	return p;
}

static const nml_operation_if* op_provide(const char *op)
{
	if (ffsz_eq(op, "cert")) op = "ssl.cert";
	else if (ffsz_eq(op, "dns")) op = "dns.dns";
	else if (ffsz_eq(op, "firewall")) op = "firewall.firewall";
	else if (ffsz_eq(op, "http")) op = "http.http";
	else if (ffsz_eq(op, "if")) op = "if.if";
	else if (ffsz_eq(op, "ping")) op = "firewall.ping";
	else if (ffsz_eq(op, "url")) op = "http.url";
	return exe_provide(op);
}

static void exe_exit(int exit_code)
{
	x->exit_code = exit_code;
}

static struct nml_exe exe_if = {
	.log = exe_log,
	.exit = exe_exit,
	.path = conf_abs_filename,
	.provide = exe_provide,
	.print = help_info_write,
};

static void conf_destroy(struct exe_conf *conf)
{
	ffstr_free(&conf->root_dir);
}

static void cleanup()
{
	if (x->op)
		x->opif->close(x->op);

	struct mod *m;
	FFSLICE_WALK(&x->mods, m) {
		mod_destroy(m);
	}
	ffvec_free(&x->mods);

	log_uninit();
	conf_destroy(&x->conf);
	ffmem_free(x);
}

int main(int argc, char **argv)
{
	x = init();
	x->exit_code = -1;
	log_init();

	if (cmd(&x->conf, argc, argv)) goto end;

	if (log_open()) goto end;
	exe_if.log_level = x->conf.log_level;
	exe_if.log_date_buffer = x->log.date;

	if (!(x->opif = op_provide(argv[x->argi]))) goto end;
	if (!(x->op = x->opif->create(&argv[x->argi + 1]))) goto end;
	sigs();
	x->exit_code = 0;
	x->opif->run(x->op);

end:
	X_DEBUG("exit code: %d", x->exit_code);
	{
	int ec = x->exit_code;
	cleanup();
	return (ec != -1) ? ec : 1;
	}
}
