/** netmill/Android: http-server: log HTTP requests
2026, Simon Zolin */

#include <http-server/conn.h>
#include <util/ipaddr.h>

struct log_entry {
	ushort ts; // time = ts * 2
	ushort resp_code;
	char host[60];
};

void logs_starting()
{
	struct http_logs *l = &x->http.logs;
	ffvec_alloc_alignT(&l->vec, 1024, 64, struct log_entry);
}

static int hs_acclog_open(nml_http_sv_conn *c)
{
	return NMLR_OPEN;
}

static int hs_acclog_process(nml_http_sv_conn *c)
{
	ffstr host = HS_REQUEST_DATA(c, c->req.host);
	char ip[16];
	uint port;
	int r = ffip_port_split(host, ip, &port);
	if (r < 0) {
		ffstr_rsplitby(&host, ':', &host, NULL);
	}
	fftime end_time = c->conf->core.date(c->conf->boss, NULL);

	struct http_logs *l = &x->http.logs;
	if (l->vec.len < l->vec.cap)
		l->vec.len++;
	struct log_entry *le = ffslice_itemT(&l->vec, l->idx, struct log_entry);
	l->idx = (l->idx + 1) % 1024;
	le->ts = (end_time.sec % (24*60*60)) / 2;
	le->resp_code = c->resp.code;
	ffsz_copystr(le->host, sizeof(le->host), &host);

	struct http_stats *hs = &x->http.stats;
	hs->rx += c->recv.transferred;
	hs->tx += c->send.transferred;
	return NMLR_DONE;
}

const nml_http_sv_component and_htsv_acclog = {
	hs_acclog_open, NULL, hs_acclog_process,
	"hs-acc-log"
};


static struct log_entry* log_entry_get(struct http_logs *l, uint i)
{
	if (l->filtered.ptr)
		return *ffslice_itemT(&l->filtered, i, struct log_entry*);
	return ffslice_itemT(&l->vec, i, struct log_entry);
}

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_logRows(JNIEnv *env, jobject thiz)
{
	dbglog("enter %s", __func__);
	struct http_logs *l = &x->http.logs;
	if (l->filtered.ptr)
		return l->filtered.len;
	return l->vec.len;
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_logsFilter(JNIEnv *env, jobject thiz, jstring jfilter)
{
	dbglog("enter %s", __func__);
	struct http_logs *l = &x->http.logs;
	const char *filter = jni_sz_js(jfilter);
	if (!*filter) {
		ffvec_free(&l->filtered);
		goto end;
	}

	l->filtered.len = 0;
	if (!l->filtered.cap)
		ffvec_allocT(&l->filtered, 64, struct log_entry*);
	struct log_entry *le;
	FFSLICE_WALK(&l->vec, le) {
		ffstr s = FFSTR_INITZ(le->host);
		if (ffstr_findz(&s, filter) >= 0)
			*ffvec_pushT(&l->filtered, struct log_entry*) = le;
	}

end:
	jni_sz_free(filter, jfilter);
}

JNIEXPORT jobjectArray JNICALL
Java_com_github_stsaz_netmill_NetMill_logDisplay(JNIEnv *env, jobject thiz, jint i, jint n)
{
	dbglog("enter %s(%d %d)", __func__, i, n);
	struct http_logs *l = &x->http.logs;
	const struct log_entry *le;
	jobjectArray jsa = jni_joa(n, jni_class(JNI_CSTR));
	uint ijsa = 0;
	n += i;
	char buf[128];
	for (;  i < n;  i++, ijsa++) {
		le = log_entry_get(l, i);

		// "HH:MM:SS HOST CODE"
		fftime t = { .sec = le->ts * 2 };
		ffdatetime dt = {};
		fftime_split1(&dt, &t);
		char *p = buf;
		p += fftime_tostr1(&dt, p, -1, FFTIME_HMS);
		ffsz_format(p, sizeof(buf) - (p - buf), " %s %u"
			, le->host, le->resp_code);

		jstring js = jni_js_sz(buf);
		jni_joa_i_set(jsa, ijsa, js);
		jni_local_unref(js);
	}
	return jsa;
}

JNIEXPORT jstring JNICALL
Java_com_github_stsaz_netmill_NetMill_logHost(JNIEnv *env, jobject thiz, jint i)
{
	dbglog("enter %s(%d)", __func__, i);
	struct http_logs *l = &x->http.logs;
	const struct log_entry *le = log_entry_get(l, i);
	jstring js = jni_js_sz(le->host);
	return js;
}
