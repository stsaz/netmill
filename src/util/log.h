/** stdout logger
2022, Simon Zolin */

#pragma once
#include <FFOS/std.h>
#include <FFOS/thread.h> // optional

struct zzlog {
	fffd fd;
	char date[32];
	char levels[10][8];
	char colors[10][8];
	ffuint stdout_color;
};

#define ZZLOG_SYS_ERROR  0x10

/**
flags: level(0..9) + ZZLOG_SYS_ERROR

TIME #TID LEVEL CTX: [ID:] MSG [: (SYSCODE) SYSERR]
*/
static inline void zzlog_printv(struct zzlog *l, ffuint flags, const char *ctx, const char *id, const char *fmt, va_list va)
{
	ffuint level = flags & 0x0f;
	char buffer[1024];
	char *d = buffer;
	ffsize r = 0, cap = sizeof(buffer) - 2;

	const char *color_end = "";
	if (l->stdout_color) {
		const char *color = l->colors[level];
		if (color[0] != '\0') {
			r = _ffs_copyz(d, cap, color);
			color_end = FFSTD_CLR_RESET;
		}
	}

	r += _ffs_copyz(&d[r], cap - r, l->date);
	d[r++] = ' ';

#ifdef FFTHREAD_NULL
	ffuint64 tid = ffthread_curid();
	d[r++] = '#';
	r += ffs_fromint(tid, &d[r], cap - r, 0);
	d[r++] = '\t';
#endif

	d[r++] = ' ';
	r += _ffs_copyz(&d[r], cap - r, l->levels[level]);
	d[r++] = '\t';

	r += _ffs_copyz(&d[r], cap - r, ctx);
	d[r++] = ':';
	d[r++] = ' ';

	if (id != NULL) {
		r += _ffs_copyz(&d[r], cap - r, id);
		d[r++] = ':';
		d[r++] = ' ';
	}

	ffssize r2 = ffs_formatv(&d[r], cap - r, fmt, va);
	if (r2 < 0)
		r2 = 0;
	r += r2;

	if (flags & ZZLOG_SYS_ERROR) {
		r += ffs_format_r0(&d[r], cap - r, ": (%u) %s"
			, fferr_last(), fferr_strptr(fferr_last()));
	}

	r += _ffs_copyz(&d[r], cap - r, color_end);

#ifdef FF_WIN
	d[r++] = '\r';
#endif
	d[r++] = '\n';

#ifdef FF_WIN
	_ffstd_write(l->fd, d, r);
#else
	write(l->fd, d, r);
#endif
}

/** Add line to log */
static inline void zzlog_print(struct zzlog *l, ffuint flags, const char *ctx, const char *id, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	zzlog_printv(l, flags, ctx, id, fmt, va);
	va_end(va);
}
