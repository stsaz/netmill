/** netmill: executor: logs
2023, Simon Zolin */

void exe_log(void *opaque, uint level, const char *ctx, const char *id, const char *fmt, ...)
{
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

	x->log.use_color = !ffstd_attr(ffstdout, FFSTD_VTERM, FFSTD_VTERM);
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
			X_SYSERR("fffile_open: %s", x->conf.log_fn);
			return -1;
		}
		x->log.fd = fd;
		x->log.use_color = 0;
	}
	return 0;
}
