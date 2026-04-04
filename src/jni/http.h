/** netmill/Android
2023, Simon Zolin */

#include <hosts-base.h>

static int http_sv_thread(void *param)
{
	struct worker *w = param;
	nml_http_server_run(w->http_sv);
	return 0;
}

static nml_wrk* htsv_worker(nml_http_server *s, struct nml_http_server_conf *hc)
{
	nml_wrk *w = hc->server.wif->create(&hc->core);
	struct nml_wrk_conf wc = {
		.opaque = s,

		.log_level = hc->log_level,
		.log = hc->log,
		.log_obj = hc->log_obj,
		.log_ctx = "http-sv",
		.log_date_buffer = hc->log_date_buffer,

		.kcq_sq = hc->kcq_sq,
		.kcq_sq_sem = hc->kcq_sq_sem,

		.timer_interval_msec = hc->server.timer_interval_msec,
		.events_num = hc->server.events_num,
		.max_connections = hc->server.max_connections,
	};
	if (hc->server.wif->conf(w, &wc)) {
		hc->server.wif->free(w);
		return NULL;
	}
	return w;
}

static int worker_start(struct worker *w, struct nml_jctx *c, struct nml_http_server_conf *sc)
{
	w->th = FFTHREAD_NULL;
	w->http_sv = nml_http_server_create();
	w->w = htsv_worker(w->http_sv, sc);
	sc->boss = w->w;
	if (nml_http_server_conf(w->http_sv, sc))
		return -1;
	w->core = sc->core;
	if (FFTHREAD_NULL == (w->th = ffthread_create(http_sv_thread, w, 0))) {
		syserrlog("ffthread_create");
		return -1;
	}
	return 0;
}

extern const nml_http_sv_component** nml_http_sv_chain(const nml_exe *exe, uint ssl);
extern const struct nml_http_client_if nml_http_client_interface;
extern const struct nml_worker_if nml_worker_interface;
extern const struct nml_tcp_listener_if nml_tcp_listener_interface;
extern const struct nml_cache_if nml_cache_interface;

extern const nml_http_sv_component
	nml_http_sv_receive,
	nml_http_sv_request,
	nml_http_sv_proxy,
	nml_http_sv_error,
	nml_http_sv_transfer,
	nml_http_sv_response,
	nml_http_sv_send,
	nml_http_sv_keepalive;

#include <jni/proxy-logs.h>
#include <jni/proxy-hosts.h>
static const nml_http_sv_component* http_server_chain_proxy[] = {
	&nml_http_sv_receive,
	&nml_http_sv_request,
	&nml_htsv_hosts,
	&nml_http_sv_proxy,
	&nml_http_sv_error,
	&nml_http_sv_transfer,
	&nml_http_sv_response,
	&nml_http_sv_send,
	&and_htsv_acclog,
	&nml_http_sv_keepalive,
	NULL
};

struct HttpServerOptions {
	jint port;
	jint workers;
	jint io_workers;
	jboolean proxy;
	jstring block_hosts_f;
	jstring www_dir;
	jstring error;
};

#define _int(name)  { #name, 'i', FF_OFF(struct HttpServerOptions, name), 0 }
#define _boolean(name)  { #name, 'z', FF_OFF(struct HttpServerOptions, name), 0 }
#define _String(name)  { #name, 's', FF_OFF(struct HttpServerOptions, name), 0 }
static struct jni_cmap HttpServerOptions_map[] = {
	_int(port),
	_int(workers),
	_int(io_workers),
	_boolean(proxy),
	_String(block_hosts_f),
	_String(www_dir),
	_String(error),
	{}
};
#undef _int
#undef _boolean
#undef _String

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStart(JNIEnv *env, jobject thiz, jobject jhso)
{
	dbglog("enter %s", __func__);
	int rc = -1;
	const char *errstr = NULL;

	jclass jc_hso = jni_class_obj(jhso);
	struct HttpServerOptions hso = {};
	jni_obj_read(env, &hso, HttpServerOptions_map, jhso, jc_hso);
	const char *www_dir = jni_sz_js(hso.www_dir);
	const char *block_hosts_f = jni_sz_js(hso.block_hosts_f);

	logs_starting();
	if (hosts_starting(block_hosts_f))
		goto end;

	if (hso.workers == 0) {
		errstr = "invalid config parameter";
		goto end;
	}

	if (hso.io_workers != 0
		&& 0 != zzkcq_create(&x->kcq, hso.io_workers, 200, /*polling*/ 0))
		goto end;

	if (zzkcq_start(&x->kcq, -1))
		goto end;

	struct nml_http_server_conf *sc = &x->sc;
	nml_http_server_conf(NULL, sc);

	if (x->log_debug)
		sc->log_level = NML_LOG_DEBUG;
#ifdef FF_DEBUG
	sc->log_level = NML_LOG_EXTRA;
#endif
	sc->log = log_bridge;
	sc->log_obj = x;

	x->addrs[0].port = hso.port;
	sc->server.listen_addresses = x->addrs;
	sc->server.max_connections = 200;
	sc->server.events_num = 100;
	sc->server.reuse_port = 1;

	ffstr_dupz(&sc->fs.www, www_dir);

	if (hso.io_workers != 0) {
		sc->kcq_sq = x->kcq.sq;
		sc->kcq_sq_sem = x->kcq.sem;
	}

	ffvec content_types = {};
	ffvec_addsz(&content_types, "text/html	html\r\n");
	nml_http_file_init(sc, *(ffstr*)&content_types);

	if (hso.proxy)
		sc->chain = (void*)http_server_chain_proxy;
	else
		sc->chain = nml_http_sv_chain(NULL, 0);

	sc->server.wif = &nml_worker_interface;
	sc->server.lsif = &nml_tcp_listener_interface;
	sc->hcif = &nml_http_client_interface;
	sc->cif = &nml_cache_interface;

	if (NULL == ffvec_zallocT(&x->workers, hso.workers, struct worker))
		goto end;
	x->workers.len = hso.workers;

	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (worker_start(w, x, sc)) {
			char *e = ffsz_allocfmt("%E", fferr_last());
			jni_obj_sz_set(env, jhso, jni_field_str(jc_hso, "error"), e);
			ffmem_free(e);
			goto end;
		}
	}
	rc = 0;

end:
	if (rc != 0) {
		if (errstr)
			jni_obj_sz_set(env, jhso, jni_field_str(jc_hso, "error"), errstr);
		ctx_destroy();
	}
	jni_sz_free(block_hosts_f, hso.block_hosts_f);
	jni_sz_free(www_dir, hso.www_dir);
	return rc;
}

static void and_http_stop(void *param)
{
	ctx_destroy();
	hosts_mod_stop();
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStop(JNIEnv *env, jobject thiz)
{
	dbglog("enter %s", __func__);
	core_task_ptr(and_http_stop, NULL);
}


struct HttpStats {
	jint received_kb, sent_kb;
};

#define _int(name)  { #name, 'i', FF_OFF(struct HttpStats, name), 0 }
static struct jni_cmap HttpStats_map[] = {
	_int(received_kb),
	_int(sent_kb),
	{}
};
#undef _int

JNIEXPORT jobject JNICALL
Java_com_github_stsaz_netmill_NetMill_httpStats(JNIEnv *env, jobject thiz)
{
	dbglog("enter %s", __func__);
	const struct http_stats *hs = &x->http.stats;
	struct HttpStats hts = {
		.received_kb = hs->rx / 1024,
		.sent_kb = hs->tx / 1024,
	};
	jobject jo = jni_obj_new(x->HttpStats.cls, x->HttpStats.init);
	jni_obj_write(env, jo, x->HttpStats.cls, HttpStats_map, &hts);
	return jo;
}
