/** netmill: executor: logs
2023, Simon Zolin */

void exe_log(void *opaque, uint level, const char *ctx, const char *id, const char *fmt, ...)
{
	struct exe *x = opaque;

	if (level > x->conf.log_level)
		return;

	va_list va;
	va_start(va, fmt);

	uint flags = level;
	if (level == NML_LOG_SYSFATAL
		|| level == NML_LOG_SYSERR
		|| level == NML_LOG_SYSWARN)
		flags |= ZZLOG_SYS_ERROR;

	zzlog_printv(&x->log, flags, ctx, id, fmt, va);
	va_end(va);
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

void log_init()
{
	x->conf.log_level = NML_LOG_INFO;
	x->log.fd = ffstdout;

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
	ffmem_copy(x->log.levels, levels, sizeof(levels));

#ifdef FF_WIN
	x->log.stdout_color = (0 == ffstd_attr(ffstdout, FFSTD_VTERM, FFSTD_VTERM));
	(void)std_console;
#else
	x->log.stdout_color = std_console(ffstdout);
#endif
	static const char colors[][8] = {
		/*NML_LOG_SYSFATAL*/FFSTD_CLR_B(FFSTD_RED),
		/*NML_LOG_SYSERR*/	FFSTD_CLR(FFSTD_RED),
		/*NML_LOG_ERR*/		FFSTD_CLR(FFSTD_RED),
		/*NML_LOG_SYSWARN*/	FFSTD_CLR(FFSTD_YELLOW),
		/*NML_LOG_WARN*/	FFSTD_CLR(FFSTD_YELLOW),
		/*NML_LOG_INFO*/	FFSTD_CLR(FFSTD_GREEN),
		/*NML_LOG_VERBOSE*/	FFSTD_CLR(FFSTD_GREEN),
		/*NML_LOG_DEBUG*/	"",
		/*NML_LOG_EXTRA*/	FFSTD_CLR_I(FFSTD_BLUE),
	};
	ffmem_copy(x->log.colors, colors, sizeof(colors));
}

void log_uninit()
{
	if (x->log.fd != ffstdout)
		fffile_close(x->log.fd);
}

int log_open()
{
	if (x->conf.log_fn) {
		fffd fd;
		if (FFFILE_NULL == (fd = fffile_open(x->conf.log_fn, FFFILE_CREATE | FFFILE_WRITEONLY | FFFILE_APPEND))) {
			syserrlog("fffile_open: %s", x->conf.log_fn);
			return -1;
		}
		x->log.fd = fd;
		x->log.stdout_color = 0;
	}
	return 0;
}
