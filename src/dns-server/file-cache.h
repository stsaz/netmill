/** netmill: dns-server: file cache
2023, Simon Zolin */

#include <dns-server/client.h>
#include <FFOS/dir.h>

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

static int nml_file_cache_req_open(nml_dns_sv_conn *c)
{
	if (c->status)
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void nml_file_cache_req_close(nml_dns_sv_conn *c)
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

static int nml_file_cache_req_process(nml_dns_sv_conn *c)
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

const struct nml_filter nml_filter_dns_file_cache_req = {
	(void*)nml_file_cache_req_open, (void*)nml_file_cache_req_close, (void*)nml_file_cache_req_process,
	"file-cache"
};


static int nml_file_cache_resp_open(nml_dns_sv_conn *c)
{
	if (!c->upstream_resp)
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void nml_file_cache_resp_close(nml_dns_sv_conn *c)
{
}

static fffd fcache_open(struct nml_dns_server_conf *conf, char *fn)
{
	fffd fd;
	if (FFFILE_NULL == (fd = fffile_open(fn, FFFILE_CREATENEW | FFFILE_WRITEONLY))) {
		if (fferr_notexist(fferr_last())) {
			ffstr s = FFSTR_INITZ(fn);
			int slash = ffstr_rfindchar(&s, '/');
			FF_ASSERT(slash >= 0);
			fn[slash] = '\0';
			if (ffdir_make(fn) && !fferr_exist(fferr_last())) {
				syserror(conf, "ffdir_make: %s", fn);
				return FFFILE_NULL;
			}
			fn[slash] = '/';

			fd = fffile_open(fn, FFFILE_CREATENEW | FFFILE_WRITEONLY);
		}
		if (fd == FFFILE_NULL) {
			syserror(conf, "fffile_open: %s", fn);
			return FFFILE_NULL;
		}
	}
	return fd;
}

/** Add entries to a file "cache/L1/DOMAIN" */
static void fcache_write(struct nml_dns_server_conf *conf, const struct dns_msg *msg)
{
	if (!conf->filecache.dir) return;

	char *fn_tmp = NULL, *fn = NULL;
	fffd fd = FFFILE_NULL;
	ffvec buf = {};

	if (!(fn_tmp = fcache_fname(conf, &msg->q, 1)))
		goto end;

	if (FFFILE_NULL == (fd = fcache_open(conf, fn_tmp)))
		goto end;

	if (!ffvec_alloc(&buf, sizeof(struct cache_ent) + msg->data.len, 1))
		goto end;
	struct cache_ent *ce = buf.ptr;
	ffmem_zero_obj(ce);

	fftime now = conf->core.date(conf->boss, NULL);
	*(ffuint64*)ce->date = ffint_be_cpu64(now.sec);

	*(uint*)ce->ttl = (msg->ttl >= 0) ? ffint_be_cpu32(msg->ttl) : 0;

	buf.len = sizeof(struct cache_ent);
	ffvec_addstr(&buf, &msg->data);

	if (buf.len != (ffsize)fffile_write(fd, buf.ptr, buf.len)) {
		syserror(conf, "fffile_write");
		goto end;
	}

	if (msg->ttl >= 0)
		now.sec += msg->ttl;
	now.sec -= FFTIME_1970_SECONDS;
	if (fffile_set_mtime(fd, &now))
		syserror(conf, "fffile_set_mtime");

	debug(conf, "written %LB to file %s", msg->data.len, fn_tmp);
	fffile_close(fd);
	fd = FFFILE_NULL;

	fn = ffsz_dupn(fn_tmp, ffsz_len(fn_tmp) - FFS_LEN(".tmp"));
	if (fffile_rename(fn_tmp, fn)) {
		syserror(conf, "fffile_rename: %s", fn);
		goto end;
	}

end:
	if (fd != FFFILE_NULL)
		fffile_close(fd);
	ffmem_free(fn_tmp);
	ffmem_free(fn);
	ffvec_free(&buf);
}

static int nml_file_cache_resp_process(nml_dns_sv_conn *c)
{
	struct nml_dns_server_conf *conf = c->conf;
	if (!conf->filecache.dir || c->respbuf_cached.len) return NMLF_DONE;

	fcache_write(conf, &c->resp);
	return NMLF_DONE;
}

const struct nml_filter nml_filter_dns_file_cache_resp = {
	(void*)nml_file_cache_resp_open, (void*)nml_file_cache_resp_close, (void*)nml_file_cache_resp_process,
	"file-cache-resp"
};

#undef syserror
#undef debug
