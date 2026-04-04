/** netmill/Android: http-server: allow/deny HTTP requests based on target host name
2026, Simon Zolin */

#include <http-server/conn.h>

static int hs_hosts_open(nml_http_sv_conn *c)
{
	struct http_hosts *h = &x->http.hosts;
	ffstr host = HS_REQUEST_DATA(c, c->req.host);
	char ip[16];
	uint port;
	int r = ffip_port_split(host, ip, &port);
	if (r < 0) {
		ffstr_rsplitby(&host, ':', &host, NULL);
	}

	uint subdomain_match = 0;
	const struct hosts_entry *he = hosts_find(&h->hosts, host, &subdomain_match);
	if (!he)
		return NMLR_SKIP;

	dbglog("host %S denied (block-hosts)", &host);
	hs_response_err(c, HTTP_403_FORBIDDEN);
	return NMLR_SKIP;
}

const nml_http_sv_component nml_htsv_hosts = {
	hs_hosts_open, NULL, NULL,
	"hs-hosts"
};

int hosts_starting(const char *block_file)
{
	struct http_hosts *h = &x->http.hosts;
	hosts_init(&h->hosts);
	ffvec d = {};
	fffile_readwhole(block_file, &d, 1*1024*1024);
	uint n = hosts_read(&h->hosts, &h->entries, *(ffstr*)&d, log_bridge, x);
	dbglog("hosts: added %u rows", n);
	h->data = *(ffstr*)&d;
	return 0;
}

void hosts_mod_stop()
{
	struct http_hosts *h = &x->http.hosts;
	hosts_destroy(&h->hosts);
	ffmem_zero_obj(&h->hosts);
	ffvec_free(&h->entries);
	ffvec_free(&h->entries_new);
	ffstr_free(&h->data);
	ffvec_free(&h->data_new);
}

JNIEXPORT jint JNICALL
Java_com_github_stsaz_netmill_NetMill_hostsRows(JNIEnv *env, jobject thiz)
{
	dbglog("enter %s", __func__);
	return x->http.hosts.entries.len + x->http.hosts.entries_new.len;
}

static struct hosts_entry* host_entry_get(struct http_hosts *h, uint i)
{
	if (i < h->entries.len) {
		return ffslice_itemT(&h->entries, i, struct hosts_entry);
	} else {
		i -= h->entries.len;
		return ffslice_itemT(&h->entries_new, i, struct hosts_entry);
	}
}

JNIEXPORT jobjectArray JNICALL
Java_com_github_stsaz_netmill_NetMill_hostsDisplay(JNIEnv *env, jobject thiz, jint i, jint n)
{
	dbglog("enter %s(%d %d)", __func__, i, n);
	struct http_hosts *h = &x->http.hosts;
	const struct hosts_entry *he = host_entry_get(h, i);
	jobjectArray jsa = jni_joa(n, jni_class(JNI_CSTR));
	uint ijsa = 0;
	n += i;
	char buf[128];
	for (;  i < n;  i++, he++, ijsa++) {
		ffsz_copyn(buf, sizeof(buf), he->host_ptr, he->host_len);

		jstring js = jni_js_sz(buf);
		jni_joa_i_set(jsa, ijsa, js);
		jni_local_unref(js);
	}
	return jsa;
}

static void and_hosts_add(void *param)
{
	char *hostz = param;
	struct http_hosts *h = &x->http.hosts;

	ffstr host = FFSTR_Z(hostz);
	if (!h->data_new.cap)
		ffvec_alloc(&h->data_new, 16*1024, 1);
	if (host.len + 1 > ffvec_unused(&h->data_new))
		goto end; // not enough space
	char *p = ffslice_end(&h->data_new, 1), *name = p;
	h->data_new.len += host.len + 1;
	p = ffmem_copy(p, host.ptr, host.len);
	*p = '\n';

	struct hosts_entry *he = ffvec_pushT(&h->entries_new, struct hosts_entry);
	he->type = T_BLOCK;
	he->host_len = host.len;
	he->host_ptr = name;

	struct hosts_entry *old;
	int r = hosts_add(&h->hosts, he, host, &old);
	if (r < 0)
		h->entries.len--;
	h->modified = 1;

end:
	ffmem_free(hostz);
}

static void and_hosts_rm(void *param)
{
	uint i = (size_t)param;
	struct http_hosts *h = &x->http.hosts;

	struct hosts_entry *he = host_entry_get(h, i);
	ffstr host = FFSTR_INITN(he->host_ptr, he->host_len);
	hosts_del(&h->hosts, host);
	he->type = 0;
	he->host_ptr = "(removed)";
	he->host_len = 9;
	h->modified = 1;
}

static void and_hosts_store(void *param)
{
	char *fn = param;
	struct http_hosts *h = &x->http.hosts;

	if (!h->modified)
		goto end;

	ffvec d = {};
	struct hosts_entry *he;
	FFSLICE_WALK(&h->entries, he) {
		if (!he->type)
			continue;
		ffvec_add(&d, he->host_ptr, he->host_len, 1);
		ffvec_addchar(&d, '\n');
	}
	FFSLICE_WALK(&h->entries_new, he) {
		if (!he->type)
			continue;
		ffvec_add(&d, he->host_ptr, he->host_len, 1);
		ffvec_addchar(&d, '\n');
	}
	int r = fffile_writewhole(fn, d.ptr, d.len, 0);
	if (r)
		syserrlog("file write: %s", fn);
	ffvec_free(&d);
	h->modified = r;

end:
	ffmem_free(fn);
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_hostsAdd(JNIEnv *env, jobject thiz, jstring jhost, jint flags)
{
	dbglog("enter %s(%d)", __func__, flags);
	const char *hostz = jni_sz_js(jhost);
	core_task_ptr(and_hosts_add, ffsz_dup(hostz));
	jni_sz_free(hostz, jhost);
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_hostsRm(JNIEnv *env, jobject thiz, jint i, jint flags)
{
	dbglog("enter %s(%d %d)", __func__, i, flags);
	core_task_ptr(and_hosts_rm, (void*)(size_t)i);
}

JNIEXPORT void JNICALL
Java_com_github_stsaz_netmill_NetMill_hostsStore(JNIEnv *env, jobject thiz, jstring jfilename)
{
	dbglog("enter %s", __func__);
	const char *fn = jni_sz_js(jfilename);
	core_task_ptr(and_hosts_store, ffsz_dup(fn));
	jni_sz_free(fn, jfilename);
}
