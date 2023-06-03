/** netmill: JNI
2023, Simon Zolin */

#include <netmill.h>
#include <FFOS/thread.h>
#include <util/jni-helper.h>
#include <ffbase/vector.h>
#include <FFOS/ffos-extern.h>
#include <android/log.h>

struct nml_jctx {
	struct nml_http_server_conf sc;
	nml_http_server *http_sv;
	struct nml_address addrs[2];
	ffthread th;
	uint log_android :1;
	uint log_debug :1;
};

static JavaVM *jvm;
extern const struct nml_filter* nml_http_server_filters[];
extern const struct nml_filter* nml_http_server_filters_proxy[];

JNIEXPORT jint JNI_OnLoad(JavaVM *_jvm, void *reserved)
{
	jvm = _jvm;
	return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_init(JNIEnv *env, jobject thiz)
{
	jclass jc = jni_class_obj(thiz);
	struct nml_jctx *c = ffmem_new(struct nml_jctx);
	jni_obj_long_set(thiz, jni_field(jc, "ctx", JNI_TLONG), (jlong)c);
	c->log_android = jni_obj_bool(thiz, jni_field(jc, "log_android", JNI_TBOOL));
	c->log_debug = jni_obj_bool(thiz, jni_field(jc, "log_debug", JNI_TBOOL));
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_destroy(JNIEnv *env, jobject thiz)
{
	jclass jc = jni_class_obj(thiz);
	struct nml_jctx *c = (void*)jni_obj_long(thiz, jni_field(jc, "ctx", JNI_TLONG));
	nml_http_server_free(c->http_sv);
	nml_http_file_uninit(&c->sc);
	ffmem_free(c);
	jni_obj_long_set(thiz, jni_field(jc, "ctx", JNI_TLONG), (jlong)NULL);
}

static void log_bridge(void *obj, ffuint level, const char *ctx, const char *id, const char *format, ...)
{
	struct nml_jctx *c = obj;
	char log_buf[1024];
	ffsize cap = sizeof(log_buf) - 1;
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

static int FFTHREAD_PROCCALL http_sv_thread(void *param)
{
	struct nml_jctx *c = param;
	nml_http_server_run(c->http_sv);
	return 0;
}

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStart(JNIEnv *env, jobject thiz)
{
	int rc = -1;
	jclass jc = jni_class_obj(thiz);
	struct nml_jctx *c = (void*)jni_obj_long(thiz, jni_field(jc, "ctx", JNI_TLONG));
	uint proxy = jni_obj_bool(thiz, jni_field(jc, "proxy", JNI_TBOOL));
	uint port = jni_obj_int(thiz, jni_field(jc, "port", JNI_TINT));
	jstring jwww_dir = jni_obj_jo(thiz, jni_field(jc, "www_dir", JNI_TSTR));
	const char *www_dir = (char*)jni_sz_js(jwww_dir);

	nml_http_server_conf(NULL, &c->sc);

	if (c->log_debug)
		c->sc.log_level = NML_LOG_DEBUG;
#ifdef FF_DEBUG
	c->sc.log_level = NML_LOG_EXTRA;
#endif
	c->sc.log = log_bridge;
	c->sc.log_obj = c;

	c->addrs[0].port = port;
	c->sc.server.listen_addresses = c->addrs;
	c->sc.server.max_connections = 200;
	c->sc.server.events_num = 100;

	ffvec content_types = {};
	ffvec_addsz(&content_types, "text/html	html\r\n");
	nml_http_file_init(&c->sc, *(ffstr*)&content_types);

	c->sc.filters = nml_http_server_filters;
	if (proxy)
		c->sc.filters = nml_http_server_filters_proxy;

	c->http_sv = nml_http_server_new();
	if (!!nml_http_server_conf(c->http_sv, &c->sc)) {
		char *e = ffsz_allocfmt("%E", fferr_last());
		jni_obj_sz_set(env, thiz, jni_field(jc, "error", JNI_TSTR), e);
		ffmem_free(e);
		nml_http_server_free(c->http_sv);  c->http_sv = NULL;
		goto end;
	}
	if (FFTHREAD_NULL == (c->th = ffthread_create(http_sv_thread, c, 0))) {
		goto end;
	}
	rc = 0;

end:
	jni_sz_free(www_dir, jwww_dir);
	return rc;
}

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStop(JNIEnv *env, jobject thiz)
{
	int r = -1;
	jclass jc = jni_class_obj(thiz);
	struct nml_jctx *c = (void*)jni_obj_long(thiz, jni_field(jc, "ctx", JNI_TLONG));
	nml_http_server_stop(c->http_sv);
	ffthread_join(c->th, -1, NULL);  c->th = FFTHREAD_NULL;
	nml_http_server_free(c->http_sv);
	c->http_sv = NULL;
	r = 0;
	return r;
}
