/** netmill: http: process command-line arguments
2022, Simon Zolin */

#include <util/cmdarg-scheme.h>
#include <util/ipaddr.h>
#include <FFOS/sysconf.h>
#include <FFOS/process.h>
#include <FFOS/path.h>
#include <FFOS/std.h>

struct nml_http_sv_conf {
	ffstr root_dir;
	uint fd_limit;
	uint workers_n;
	uint cpumask;
	uint kcall_workers;
	ffbyte proxy;

	struct nml_address listen_addr[2];
	struct nml_http_server_conf aconf;
};

#define R_DONE  100
#define R_BADVAL  101

static int ip_port_split(ffstr s, void *ip6, ffushort *port)
{
	int r = 0;
	if (s.ptr[0] == '[') {
		r = ffip6_parse(ip6, s.ptr+1, s.len-1);
		if (r <= 0 || s.ptr[r+1] != ']')
			return -1;
		r += 2;
	} else {
		char ip4[4];
		r = ffip4_parse((void*)ip4, s.ptr, s.len);
		if (r > 0)
			ffip6_v4mapped_set(ip6, (void*)ip4);
		else
			r = 0;
	}

	if (r > 0) {
		if (s.ptr[r] != ':')
			return -1;
		ffstr_shift(&s, r+1);
	}

	if (!ffstr_toint(&s, port, FFS_INT16))
		return -1;
	return 0;
}

static int cmd_listen(void *cs, struct nml_http_sv_conf *conf, ffstr *val)
{
	if (0 != ip_port_split(*val, conf->listen_addr[0].ip, (ffushort*)&conf->listen_addr[0].port))
		return R_BADVAL;
	conf->aconf.server.listen_addresses = conf->listen_addr;
	return 0;
}

static int cmd_debug(void *cs, struct nml_http_sv_conf *conf)
{
	conf->aconf.log_level = NML_LOG_DEBUG;
	return 0;
}

static int cmd_cpumask(void *cs, struct nml_http_sv_conf *conf, ffstr *val)
{
	if (!ffstr_toint(val, &conf->cpumask, FFS_INT32 | FFS_INTHEX))
		return R_BADVAL;
	return 0;
}

static int cmd_help()
{
	static const char help[] =
"Options:\n"
"-l, --listen ADDR   Listening IP and TCP port (def: 80)\n"
"                      e.g. 8080 or 127.0.0.1:8080 or [::1]:8080\n"
"-w, --www DIR       Web directory (def: www)\n"
"-x, --proxy         Act as a proxy (disable serving local files from 'www')\n"
"-t, --threads N     Worker threads (def: CPU#)\n"
"-c, --cpumask N     CPU affinity bitmask, hex value (e.g. 15 for CPUs 0,2,4)\n"
"-k, --kcall-threads N\n"
"                    kcall worker threads (def: CPU#)\n"
"-p, --polling       Active polling mode\n"
"-D, --debug         Debug log level\n"
"-h, --help          Show help\n"
;
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

static const ffcmdarg_arg cmd_args[] = {
	{ 'l', "listen",	FFCMDARG_TSTR | FFCMDARG_FNOTEMPTY, (ffsize)cmd_listen },
	{ 'w', "www",	FFCMDARG_TSTR | FFCMDARG_FNOTEMPTY, FF_OFF(struct nml_http_sv_conf, aconf.fs.www) },
	{ 'x', "proxy",	FFCMDARG_TSWITCH, FF_OFF(struct nml_http_sv_conf, proxy) },
	{ 't', "threads",	FFCMDARG_TINT32, FF_OFF(struct nml_http_sv_conf, workers_n) },
	{ 'k', "kcall-threads",	FFCMDARG_TINT32, FF_OFF(struct nml_http_sv_conf, kcall_workers) },
	{ 'c', "cpumask",	FFCMDARG_TSTR, (ffsize)cmd_cpumask },
	{ 'p', "polling",	FFCMDARG_TSWITCH, FF_OFF(struct nml_http_sv_conf, aconf.server.polling_mode) },
	{ 'D', "debug",	FFCMDARG_TSWITCH, (ffsize)cmd_debug },
	{ 'h', "help",	FFCMDARG_TSWITCH, (ffsize)cmd_help },
	{}
};

void conf_destroy(struct nml_http_sv_conf *conf)
{
	nml_http_file_uninit(&conf->aconf);

	ffstr_free(&conf->aconf.fs.www);
	ffstr_free(&conf->root_dir);
}

void conf_init(struct nml_http_sv_conf *conf)
{
	struct nml_http_server_conf *ac = &conf->aconf;
	nml_http_server_conf(NULL, ac);
	ffstr_dupz(&ac->fs.www, "www");

	conf->fd_limit = ac->server.max_connections * 2;
	conf->kcall_workers = ~0;
}

static int cmd_fin(struct nml_http_sv_conf *conf)
{
	if (!(conf->aconf.receive.buf_size > 16 && conf->aconf.response.buf_size > 16)) {
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

int cmd_read(struct nml_http_sv_conf *conf, int argc, const char **argv)
{
	char fn[4096];
	const char *p;
	if (NULL == (p = ffps_filename(fn, sizeof(fn), argv[0])))
		return -1;
	ffstr path;
	if (0 > ffpath_splitpath(p, ffsz_len(p), &path, NULL))
		return -1;
	if (NULL == ffstr_dup(&conf->root_dir, path.ptr, path.len + 1))
		return -1;

	ffstr errmsg = {};
	int r = ffcmdarg_parse_object(cmd_args, conf, argv, argc, 0, &errmsg);
	if (r < 0) {
		if (r == -R_DONE)
			return -1;
		else if (r == -R_BADVAL)
			ffstderr_fmt("command line: bad value\n");
		else
			ffstderr_fmt("command line: %S\n", &errmsg);
		return -1;
	}
	if (0 != cmd_fin(conf))
		return -1;
	return 0;
}

/** Convert relative file name to absolute file name using application directory */
char* conf_abs_filename(struct nml_http_sv_conf *conf, const char *rel_fn)
{
	return ffsz_allocfmt("%S%s", &conf->root_dir, rel_fn);
}
