/** netmill/Android
2023, Simon Zolin */

#include <netmill-http.h>
#include <util/jni-helper.h>
#include <util/kcq.h>
#include <ffsys/thread.h>
#include <ffsys/globals.h>
#include <ffbase/vector.h>

struct http_logs {
	uint idx;
	ffvec vec; // struct log_entry[]
	ffvec filtered; // struct log_entry*[]
};

struct http_hosts {
	struct hosts hosts;
	ffvec entries, entries_new; // struct hosts_entry[]
	ffstr data; // (host LF)...
	ffvec data_new; // (host LF)...
	uint modified :1;
};

struct http_stats {
	uint64 rx, tx;
};

struct nml_jctx {
	struct zzkcq kcq;
	struct nml_http_server_conf sc;
	struct nml_address addrs[2];
	ffvec workers; // struct worker[]
	uint log_android :1;
	uint log_debug :1;

	struct {
		struct http_logs logs;
		struct http_hosts hosts;
		struct http_stats stats;
	} http;

	struct jni_class_t HttpStats;
	struct jni_class_t UtilNative_Files;
};
static struct nml_jctx *x;

#include <jni/log.h>

struct worker {
	nml_wrk *w;
	nml_core core;
	ffthread th;
	nml_http_server *http_sv;
};

struct core_task {
	nml_task tsk;
	void (*func)(void *param);
	void *param;
};

static void core_task_func(struct core_task *t)
{
	t->func(t->param);
	ffmem_free(t);
}

static void core_task_ptr(void (*func)(void *param), void *param)
{
	struct core_task *t = ffmem_new(struct core_task);
	t->func = func;
	t->param = param;
	t->tsk.handler = (fftask_handler)core_task_func;
	t->tsk.param = t;
	struct worker *w = ffslice_itemT(&x->workers, 0, struct worker);
	w->core.task(w->w, &t->tsk, 1);
}


static JavaVM *jvm;

JNIEXPORT jint JNI_OnLoad(JavaVM *_jvm, void *reserved)
{
	jvm = _jvm;
	return JNI_VERSION_1_6;
}

static void workers_free()
{
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (w->http_sv == NULL) continue;

		nml_http_server_stop(w->http_sv);
		ffthread_join(w->th, -1, NULL);  w->th = FFTHREAD_NULL;
		nml_http_server_free(w->http_sv);  w->http_sv = NULL;
	}
	ffvec_free(&x->workers);
}

static void ctx_destroy()
{
	zzkcq_destroy(&x->kcq);  ffmem_zero_obj(&x->kcq);
	workers_free();
	nml_http_file_uninit(&x->sc);
	ffstr_free(&x->sc.fs.www);
	ffmem_zero_obj(&x->http.stats);
}

struct NetMill {
	jboolean log_android;
	jboolean log_debug;
};
#define _boolean(name)  { #name, 'z', FF_OFF(struct NetMill, name), 0 }
static struct jni_cmap NetMill_map[] = {
	_boolean(log_android),
	_boolean(log_debug),
};
#undef _boolean

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_init(JNIEnv *env, jobject thiz)
{
	x = ffmem_new(struct nml_jctx);

	jclass jc = jni_class_obj(thiz);
	struct NetMill nm = {};
	jni_obj_read(env, &nm, NetMill_map, thiz, jc);

	x->log_android = nm.log_android;
	x->log_debug = nm.log_debug;
#ifdef FF_DEBUG
	x->log_debug = 1;
#endif

	jni_class_set(env, &x->HttpStats, "com/github/stsaz/netmill/NetMill$HttpStats");
	jni_class_set(env, &x->UtilNative_Files, "com/github/stsaz/netmill/UtilNative$Files");
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_destroy(JNIEnv *env, jobject thiz)
{
	ctx_destroy();
	jni_global_unref(x->HttpStats.cls);
	jni_global_unref(x->UtilNative_Files.cls);
	ffmem_free(x);
	x = NULL;
}

JNIEXPORT jstring JNICALL
Java_com_github_stsaz_netmill_NetMill_version(JNIEnv *env, jobject thiz)
{
	return jni_js_sz(NML_VERSION);
}

#include <jni/android-utils.h>
#include <jni/conf.h>
#include <jni/http.h>

#include <util/ipaddr.h>
#include <ffsys/netconf.h>

enum {
	IP_NOLOCAL = 1,
};

/** Get IP addresses from 'struct nml_nif_info' and convert them to String[] */
JNIEXPORT jobjectArray JNICALL
Java_com_github_stsaz_netmill_NetMill_listIPAddresses(JNIEnv *env, jobject thiz, jint flags)
{
	ffvec ips = {};

	struct nml_nif_info ni = {};
	ffslice nifs = {};
	nml_nif_info(&ni, &nifs);

	struct ffnetconf_ifinfo **pnif;
	FFSLICE_WALK(&nifs, pnif) {
		struct ffnetconf_ifinfo *nif = *pnif;
		for (uint i = 0;  i < nif->ip_n;  i++) {
			const ffip6 *ip = nif->ip[i];

			if (flags & IP_NOLOCAL) {
				const ffip4 *ip4 = ffip6_v4mapped(ip);
				if ((ip4 && ffip4_loopback(ip4) && ffip4_linklocal(ip4))
					|| (!ip4 && !ffip6_public(ip)))
					continue;
			}

			char buf[100];
			int r = ffip46_tostr(ip, buf, sizeof(buf));
			buf[r] = '\0';
			*ffvec_pushT(&ips, char*) = ffsz_dup(buf);
		}
	}

	jobjectArray jsa = jni_jsa_sza(env, ips.ptr, ips.len);

	nml_nif_info_destroy(&ni);

	char **it;
	FFSLICE_WALK(&ips, it) {
		ffmem_free(*it);
	}
	ffvec_free(&ips);

	return jsa;
}
