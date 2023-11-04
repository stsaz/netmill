/** netmill: JNI
2023, Simon Zolin */

#include <netmill.h>
#include <util/jni-helper.h>
#include <util/kcq.h>
#include <util/ipaddr.h>
#include <ffsys/thread.h>
#include <ffsys/globals.h>
#include <ffbase/vector.h>
#include <android/log.h>

struct nml_jctx {
	struct zzkcq kcq;
	struct nml_http_server_conf sc;
	struct nml_address addrs[2];
	ffvec workers; // struct worker[]
	uint log_android :1;
	uint log_debug :1;
};

struct worker {
	ffthread th;
	nml_http_server *http_sv;
};

static JavaVM *jvm;
extern const struct nml_filter* nml_http_server_filters[];
extern const struct nml_filter* nml_http_server_filters_proxy[];

JNIEXPORT jint JNI_OnLoad(JavaVM *_jvm, void *reserved)
{
	jvm = _jvm;
	return JNI_VERSION_1_6;
}

static void workers_free(struct nml_jctx *c)
{
	struct worker *w;
	FFSLICE_WALK(&c->workers, w) {
		if (w->http_sv == NULL) continue;

		nml_http_server_stop(w->http_sv);
		ffthread_join(w->th, -1, NULL);  w->th = FFTHREAD_NULL;
		nml_http_server_free(w->http_sv);  w->http_sv = NULL;
	}
	ffvec_free(&c->workers);
}

static int FFTHREAD_PROCCALL http_sv_thread(void *param)
{
	struct worker *w = param;
	nml_http_server_run(w->http_sv);
	return 0;
}

static int worker_start(struct worker *w, struct nml_jctx *c, struct nml_http_server_conf *sc)
{
	w->th = FFTHREAD_NULL;
	w->http_sv = nml_http_server_new();
	if (!!nml_http_server_conf(w->http_sv, sc))
		return -1;
	if (FFTHREAD_NULL == (w->th = ffthread_create(http_sv_thread, w, 0)))
		return -1;
	return 0;
}

static void ctx_destroy(struct nml_jctx *c)
{
	zzkcq_destroy(&c->kcq);  ffmem_zero_obj(&c->kcq);
	workers_free(c);
	nml_http_file_uninit(&c->sc);
	ffstr_free(&c->sc.fs.www);
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
	ctx_destroy(c);
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

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStart(JNIEnv *env, jobject thiz, jobject jhso)
{
	int rc = -1;
	jclass jc = jni_class_obj(thiz);
	struct nml_jctx *c = (void*)jni_obj_long(thiz, jni_field(jc, "ctx", JNI_TLONG));

	jclass jc_hso = jni_class_obj(jhso);
	uint proxy = jni_obj_bool(jhso, jni_field(jc_hso, "proxy", JNI_TBOOL));
	uint port = jni_obj_int(jhso, jni_field(jc_hso, "port", JNI_TINT));
	uint workers = jni_obj_int(jhso, jni_field(jc_hso, "workers", JNI_TINT));
	uint io_workers = jni_obj_int(jhso, jni_field(jc_hso, "io_workers", JNI_TINT));
	jstring jwww_dir = jni_obj_jo(jhso, jni_field(jc_hso, "www_dir", JNI_TSTR));
	const char *www_dir = (char*)jni_sz_js(jwww_dir);

	if (workers == 0) {
		jni_obj_sz_set(env, jhso, jni_field(jc_hso, "error", JNI_TSTR), "invalid config parameter");
		goto end;
	}

	if (io_workers != 0
		&& 0 != zzkcq_create(&c->kcq, io_workers, 200, /*polling*/ 0))
		goto end;

	if (0 != zzkcq_start(&c->kcq))
		goto end;

	struct nml_http_server_conf *sc = &c->sc;
	nml_http_server_conf(NULL, sc);

	if (c->log_debug)
		sc->log_level = NML_LOG_DEBUG;
#ifdef FF_DEBUG
	sc->log_level = NML_LOG_EXTRA;
#endif
	sc->log = log_bridge;
	sc->log_obj = c;

	c->addrs[0].port = port;
	sc->server.listen_addresses = c->addrs;
	sc->server.max_connections = 200;
	sc->server.events_num = 100;
	sc->server.reuse_port = 1;

	ffstr_dupz(&sc->fs.www, www_dir);

	if (io_workers != 0) {
		sc->kcq_sq = c->kcq.sq;
		sc->kcq_sq_sem = c->kcq.sem;
	}

	ffvec content_types = {};
	ffvec_addsz(&content_types, "text/html	html\r\n");
	nml_http_file_init(sc, *(ffstr*)&content_types);

	sc->filters = nml_http_server_filters;
	if (proxy)
		sc->filters = nml_http_server_filters_proxy;

	if (NULL == ffvec_zallocT(&c->workers, workers, struct worker))
		goto end;
	c->workers.len = workers;

	struct worker *w;
	FFSLICE_WALK(&c->workers, w) {
		if (!!worker_start(w, c, sc)) {
			char *e = ffsz_allocfmt("%E", fferr_last());
			jni_obj_sz_set(env, jhso, jni_field(jc_hso, "error", JNI_TSTR), e);
			ffmem_free(e);
			goto end;
		}
	}
	rc = 0;

end:
	if (rc != 0) {
		ctx_destroy(c);
	}
	jni_sz_free(www_dir, jwww_dir);
	return rc;
}

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStop(JNIEnv *env, jobject thiz)
{
	int r = -1;
	jclass jc = jni_class_obj(thiz);
	struct nml_jctx *c = (void*)jni_obj_long(thiz, jni_field(jc, "ctx", JNI_TLONG));
	ctx_destroy(c);
	r = 0;
	return r;
}

/** Get IP addresses from 'struct nml_nif_info' and convert them to String[] */
JNIEXPORT jobjectArray JNICALL
Java_com_github_stsaz_netmill_NetMill_listIPAddresses(JNIEnv *env, jobject thiz)
{
	ffvec ips = {};

	struct nml_nif_info i = {};
	nml_nif_info(&i);

	struct nml_nif *nif;
	FFSLICE_WALK(&i.nifs, nif) {
		char buf[100];
		int r = ffip46_tostr((void*)nif->ip, buf, sizeof(buf));
		buf[r] = '\0';
		*ffvec_pushT(&ips, char*) = ffsz_dup(buf);
	}

	jobjectArray jsa = jni_jsa_sza(env, ips.ptr, ips.len);

	nml_nif_info_destroy(&i);

	char **it;
	FFSLICE_WALK(&ips, it) {
		ffmem_free(*it);
	}
	ffvec_free(&ips);

	return jsa;
}
