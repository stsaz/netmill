/** netmill: executor: service: process command-line arguments
2023, Simon Zolin */

struct svc_conf {
	ffvec cmd;
};

static int svc_install_cmd(struct svc_conf *sc, const char *val)
{
	ffstr s = FFSTR_INITZ(val);
	if (ffstr_findchar(&s, ' ') >= 0)
		ffvec_addfmt(&sc->cmd, "'%s' ", val);
	else
		ffvec_addfmt(&sc->cmd, "%s ", val);
	return 0;
}

static int svc_install(const char *fn, ffstr cmd, const char *description, const char *after)
{
	const char *template_systemd =
"[Unit]\n\
Description=%s\n\
DefaultDependencies=false\n\
After=%s\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=%S\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";

	ffstr data = {};
	ffsize cap = 0;
	ffstr_growfmt(&data, &cap, template_systemd
		, description, after, &cmd);
	int r = fffile_writewhole(fn, data.ptr, data.len, 0);
	ffstr_free(&data);
	return r;
}

static int svc_install_fin(struct svc_conf *sc)
{
	const char *fn = "/usr/lib/systemd/system/netmill.service";
	if (svc_install(fn, *(ffstr*)&sc->cmd, "netmill server", "network.target")) {
		syserrlog("file write: %s", fn);
		return 102;
	}
	infolog("installed service: %s", fn);

	ffvec_free(&sc->cmd);
	ffmem_free(sc);
	return R_DONE;
}

static const struct ffarg svc_install_args[] = {
	{ "\0\1",	's',	svc_install_cmd },
	{ "",		'1',	svc_install_fin }
};

static int svc_help()
{
	static const char help[] = "\
Install service (systemd)\n\
    netmill service install /path/to/netmill COMMAND [OPTIONS]\n\
";
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

static const struct ffarg svc_args[] = {
	{ "help",		'1',	svc_help },
	{ "install",	'>',	svc_install_args },
	{}
};

struct ffarg_ctx svc_ctx(void *o)
{
	x->conf.svc = ffmem_new(struct svc_conf);
	struct ffarg_ctx ax = { svc_args, x->conf.svc };
	return ax;
}
