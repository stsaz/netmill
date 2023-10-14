/** netmill: executor
2022, Simon Zolin */

#include <netmill.h>
#include <exe/shared.h>
#include <util/log.h>
#include <FFOS/signal.h>
#include <FFOS/thread.h>
#include <FFOS/process.h>
#include <FFOS/path.h>
#include <FFOS/ffos-extern.h>
#include <ffbase/args.h>
#ifdef FF_UNIX
#include <sys/resource.h>
#endif

struct exe *x;

/** Convert relative file name to absolute file name using application directory */
char* conf_abs_filename(const char *rel_fn)
{
	if (ffpath_abs(rel_fn, ffsz_len(rel_fn)))
		return ffsz_dup(rel_fn);
	return ffsz_allocfmt("%S%s", &x->conf.root_dir, rel_fn);
}

#include <exe/log.h>
#include <exe/service.h>
#include <exe/if.h>

static int cmd_debug(struct exe_conf *conf)
{
	conf->log_level = NML_LOG_DEBUG;
	return 0;
}

static int usage()
{
	static const char help[] = "\
Usage:\n\
    netmill [GLOBAL-OPTIONS] COMMAND [OPTIONS]\n\
\n\
Global options:\n\
  -help             Show help\n\
  -Debug            Print debug logs\n\
  -log FILE         Print logs to file\n\
\n\
Command:\n\
  cert          Generate certificate+key PEM file\n\
  dns           Start DNS server\n\
  http          Start HTTP server\n\
  if            Show network interfaces\n\
  service       Install system service\n\
  url           Execute HTTP request\n\
\n\
`netmill COMMAND help` will print details on each command.\n\
";
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct exe_conf, m)
static const struct ffarg nml_args[] = {
	{ "-Debug",		'1',	cmd_debug },

	{ "-help",		'1',	usage },
	{ "-log",		's',	O(log_fn) },
	{ "cert",		'{',	cert_ctx },
	{ "dns",		'{',	dns_ctx },
	{ "http",		'{',	http_ctx },
	{ "if",			'1',	nif_info },
	{ "service",	'{',	svc_ctx },
	{ "url",		'{',	url_ctx },
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

static const job_if* cmd(struct exe_conf *conf, int argc, char **argv)
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

	if (conf_root_dir(conf, argv[0])) return NULL;

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, nml_args, conf, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv+1, argc-1);
	if (r) {
		if (r == R_DONE)
		{}
		else if (r == R_BADVAL)
			ffstderr_fmt("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			ffstderr_fmt("command line: %s\n", as.error);
		return NULL;
	}

	return x->job;
}

static struct exe* init()
{
	static const char appname[] = "netmill v" NML_VERSION "\n";
	ffstdout_write(appname, FFS_LEN(appname));

	struct exe *c = ffmem_new(struct exe);
	c->conn_id = 1;
	return c;
}

static void conf_destroy(struct exe_conf *conf)
{
	ffstr_free(&conf->root_dir);
}

static void cleanup()
{
	if (x->job)
		x->job->destroy();
	log_uninit();
	zzkcq_destroy(&x->kcq);
	ffvec_free(&x->workers);
	conf_destroy(&x->conf);
	ffmem_free(x);
}

static void onsig(struct ffsig_info *i)
{
	x->job->stop();
}

static void sigs()
{
	static const uint sigs[] = { FFSIG_INT };
	ffsig_subscribe(onsig, sigs, FF_COUNT(sigs));
}

int main(int argc, char **argv)
{
	int exit_code = 1;
	x = init();
	log_init();
	if (!(x->job = cmd(&x->conf, argc, argv)))
		goto end;
	if (log_open())
		goto end;
	if (x->job->setup())
		goto end;
	sigs();
	if (x->job->run())
		goto end;
	exit_code = 0;

end:
	cleanup();
	return exit_code;
}
