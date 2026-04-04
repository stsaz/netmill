/** netmill/Android: logger
2023, Simon Zolin */

#include <android/log.h>

static void log_bridge(void *obj, ffuint level, const char *ctx, const char *id, const char *format, ...)
{
	struct nml_jctx *c = obj;
	char log_buf[1024];
	size_t cap = sizeof(log_buf) - 1;
	ffstr s = FFSTR_INITN(log_buf, 0);

	ffstr_addfmt(&s, cap, "%s: %s: ", ctx, id);

	va_list va;
	va_start(va, format);
	ffstr_addfmtv(&s, cap, format, va);

	if (level == NML_LOG_SYSFATAL
		|| level == NML_LOG_SYSERR
		|| level == NML_LOG_SYSWARN)
		ffstr_addfmt(&s, cap, ": (%u) %s", fferr_last(), fferr_strptr(fferr_last()));

	ffstr_addchar(&s, cap, '\0');

	if (c->log_android) {
		static const uint android_levels[] = {
			/*NML_LOG_SYSFATAL*/	ANDROID_LOG_ERROR,
			/*NML_LOG_SYSERR*/	ANDROID_LOG_ERROR,
			/*NML_LOG_ERR*/	ANDROID_LOG_ERROR,
			/*NML_LOG_SYSWARN*/	ANDROID_LOG_WARN,
			/*NML_LOG_WARN*/	ANDROID_LOG_WARN,
			/*NML_LOG_INFO*/	ANDROID_LOG_INFO,
			/*NML_LOG_VERBOSE*/	ANDROID_LOG_INFO,
			/*NML_LOG_DEBUG*/	ANDROID_LOG_DEBUG,
			/*NML_LOG_EXTRA*/	ANDROID_LOG_DEBUG,
		};
		__android_log_print(android_levels[level], "netmill", "%s", s.ptr);
	}

	va_end(va);
}

#define syserrlog(...) \
	log_bridge(x, NML_LOG_SYSERR, NULL, NULL, __VA_ARGS__)

#define errlog(...) \
	log_bridge(x, NML_LOG_ERR, NULL, NULL, __VA_ARGS__)

#define dbglog(...) \
do { \
	if (ff_unlikely(x->log_debug)) \
		log_bridge(x, NML_LOG_DEBUG, NULL, NULL, __VA_ARGS__); \
} while (0)
