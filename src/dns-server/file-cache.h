/** netmill: dns-server: file cache
2023, Simon Zolin */

#include <dns-server/client.h>
#include <ffsys/dir.h>

#define syserror(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_SYSERR, "file-cache", NULL, __VA_ARGS__)

#define debug(conf, ...) \
do { \
	if (conf->log_level >= NML_LOG_DEBUG) \
		conf->log(conf->log_obj, NML_LOG_DEBUG, "file-cache", NULL, __VA_ARGS__); \
} while (0)

int nml_dns_filecache_init(struct nml_dns_server_conf *conf)
{
	if (!conf->filecache.dir) return 0;

	if (ffdir_make(conf->filecache.dir)
		&& !fferr_exist(fferr_last())) {
		syserror(conf, "ffdir_make: %s", conf->filecache.dir);
		return -1;
	}
	return 0;
}

static int dns_file_cache_req_open(nml_dns_sv_conn *c)
{
	if (c->status)
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void dns_file_cache_req_close(nml_dns_sv_conn *c)
{
	ffstr_free(&c->respbuf_cached);
}

/** Get file name */
static char* fcache_fname(struct nml_dns_server_conf *conf, const ffdns_question *q, ffbool tmp)
{
	if (!q->name.len) return NULL;

	ffstr l1, qname = FFSTR_INITSTR(&q->name);
	qname.len--;
	ffstr_rsplitby(&qname, '.', NULL, &l1);

	ffvec fn = {};
	if (!tmp) {
		if (!ffvec_addfmt(&fn, "%s/%S/%S.%u%Z", conf->filecache.dir, &l1, &qname, q->type))
			return NULL;
	} else {
		if (!ffvec_addfmt(&fn, "%s/%S/%S.%u.tmp%Z", conf->filecache.dir, &l1, &qname, q->type))
			return NULL;
	}
	return fn.ptr;
}

struct cache_ent {
	char reserved[4];
	char ttl[4];
	char date[8];
	char body[0];
};

/** Read response from file.
buf: newly allocated buffer
body: response body
Return TTL */
static struct cache_ent* fcache_fetch(struct nml_dns_sv_conn *c, ffstr *buf, ffstr *body)
{
	struct nml_dns_server_conf *conf = c->conf;
	if (!conf->filecache.dir) return NULL;

	struct cache_ent *ce = NULL;
	ffvec v = {};
	char *fn;

	if (!(fn = fcache_fname(conf, &c->req.q, 0)))
		goto end;

	if (fffile_readwhole(fn, &v, 64*1024)) {
		if (!fferr_notexist(fferr_last()))
			syserror(conf, "fffile_readwhole: %s", fn);
		goto end;
	}

	ce = v.ptr;
	debug(conf, "fetched %s", fn);

	*buf = *(ffstr*)&v;
	ffvec_null(&v);

	*body = *buf;
	ffstr_shift(body, sizeof(struct cache_ent));

end:
	ffmem_free(fn);
	ffvec_free(&v);
	return ce;
}

/** Set TTL value on all answer records */
static void dns_answers_ttl_set(ffstr resp, uint ttl)
{
	ffdns_header h = {};
	uint i = ffdns_header_read(&h, resp);
	i += ffdns_question_read(NULL, resp);
	for (uint ia = 0;  ia != h.answers;  ia++) {
		int aoff = ffdns_name_read(NULL, resp, i);
		struct ffdns_ans *a = (struct ffdns_ans*)&resp.ptr[i + aoff];
		*(uint*)a->ttl = ffint_be_cpu32(ttl);
		i += ffdns_answer_read(NULL, resp, i);
	}
}

static int dns_file_cache_req_process(nml_dns_sv_conn *c)
{
	struct nml_dns_server_conf *conf = c->conf;
	if (!conf->filecache.dir) return NMLF_DONE;

	ffstr resp;
	const struct cache_ent *ce = fcache_fetch(c, &c->respbuf_cached, &resp);
	if (!ce)
		return NMLF_DONE; // not found in cache
	struct ffdns_hdr *h = (struct ffdns_hdr*)resp.ptr;

	uint ttl = ffint_be_cpu32_ptr(ce->ttl);
	ffuint64 expire_sec = ffint_be_cpu64_ptr(ce->date);
	if (h->rcode == FFDNS_NOERROR)
		ttl = ffmax(ttl, conf->filecache.min_ttl);
	else
		ttl = ffmax(ttl, conf->filecache.error_ttl);
	expire_sec += ttl;

	fftime now = conf->core.date(conf->boss, NULL);
	if (now.sec >= expire_sec) {
		debug(conf, "%S: expired", &c->req.q.name);
		ffstr_free(&c->respbuf_cached);
		return NMLF_DONE;
	}

	dns_answers_ttl_set(resp, ttl);

	*(ffushort*)h->id = ffint_be_cpu16(c->req.h.id);

	ffvec_set(&c->respbuf, resp.ptr, resp.len);
	c->status = "cache";
	return NMLF_DONE;
}

const nml_dns_component nml_dns_file_cache_req = {
	dns_file_cache_req_open, dns_file_cache_req_close, dns_file_cache_req_process,
	"file-cache"
};

#include <dns-server/file-cache-resp.h>

#undef syserror
#undef debug
