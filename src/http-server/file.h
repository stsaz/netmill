/** netmill: http-server: static file filter/module
2022, Simon Zolin */

#include <http-server/conn.h>
#include <ffsys/kcall.h>
#include <ffbase/conf.h>
#include <ffbase/map.h>

static int hs_file_open(nml_http_sv_conn *c)
{
	if (c->resp_err || c->resp.code != 0)
		return NMLR_SKIP;

	c->file.f = FFFILE_NULL;

	ffstr method = HS_REQUEST_DATA(c, c->req.method);
	if (!(ffstr_eqz(&method, "GET")
			|| (c->req_method_head = ffstr_eqz(&method, "HEAD")))) {
		hs_response_err(c, HTTP_405_METHOD_NOT_ALLOWED);
		return NMLR_SKIP;
	}

	if (c->conf->fs.www.len + c->req.unescaped_path.len + 1 > c->conf->fs.file_buf_size) {
		HS_WARN(c, "too small file buffer");
		return NMLR_ERR;
	}
	if (NULL == ffvec_alloc(&c->file.buf, c->conf->fs.file_buf_size, 1)) {
		HS_ERR(c, "no memory");
		hs_response_err(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return NMLR_SKIP;
	}
	ffstr *fn = (ffstr*)&c->file.buf;
	ffstr_add2(fn, -1, &c->conf->fs.www);
	ffstr_add2(fn, -1, &c->req.unescaped_path);
	fn->ptr[fn->len] = '\0';

	return NMLR_OPEN;
}

static void hs_file_close(nml_http_sv_conn *c)
{
	if (c->file.f != FFFILE_NULL) {
		fffile_close(c->file.f);
		c->file.f = FFFILE_NULL;
	}
	ffvec_free(&c->file.buf);
}

static int handle_redirect(nml_http_sv_conn *c, const fffileinfo *fi)
{
	if (!fffile_isdir(fffileinfo_attr(fi)))
		return 0;

	HS_DEBUG(c, "handle_redirect: %s", c->file.buf.ptr);
	hs_response_err(c, HTTP_301_MOVED_PERMANENTLY);

	ffstr host = HS_REQUEST_DATA(c, c->req.host);
	ffstr path = HS_REQUEST_DATA(c, c->req.path);
	// TODO a bad client may set Host header value without specifying the non-standard port
	c->file.buf.len = ffs_format_r0(c->file.buf.ptr, c->file.buf.cap, "http://%S%S/"
		, &host, &path);
	ffstr_setstr(&c->resp.location, &c->file.buf);
	return -1;
}

static int mtime(nml_http_sv_conn *c, const fffileinfo *fi)
{
	fftime mt = fffileinfo_mtime(fi);
	mt.sec += FFTIME_1970_SECONDS;
	ffdatetime dt;
	fftime_split1(&dt, &mt);
	int r = FFS_LEN("Wed, dd Sep yyyy hh:mm:ss GMT")+1;
	if (NULL == ffstr_alloc(&c->resp.last_modified, r)) {
		HS_ERR(c, "no memory");
		hs_response_err(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return -1;
	}
	c->resp.last_modified.len = fftime_tostr1(&dt, c->resp.last_modified.ptr, r, FFTIME_WDMY);

	if (c->req.if_modified_since.len) {
		ffstr ims = HS_REQUEST_DATA(c, c->req.if_modified_since);
		if (ffstr_eq2(&c->resp.last_modified, &ims)) {
			hs_response_err(c, HTTP_304_NOT_MODIFIED);
			return -1;
		}
	}
	return 0;
}

static int ctmap_keyeq(void *opaque, const void *key, size_t keylen, void *val)
{
	nml_http_sv_conn *c = opaque;
	uint hi = (uint64)val >> 32;
	ffstr k = range16_tostr((range16*)&hi, c->conf->fs.content_types_data);
	return ffstr_eq(&k, key, keylen);
}

void nml_http_file_init(struct nml_http_server_conf *conf, ffstr content_types)
{
	conf->fs.content_types_data = content_types.ptr;

	ffmap_init(&conf->fs.content_types_map, ctmap_keyeq);
	ffmap_alloc(&conf->fs.content_types_map, 16);
	ffstr in = content_types, out, ct = {};
	struct ffconf c = {};

	for (;;) {
		int r = ffconf_read(&c, &in, &out);

		switch (r) {
		case FFCONF_KEY:
			ct = out;
			break;
		case FFCONF_VAL:
		case FFCONF_VAL_NEXT: {
			if (out.len > 4)
				return;
			range16 k, v;
			range16_set(&k, out.ptr - content_types.ptr, out.len);
			range16_set(&v, ct.ptr - content_types.ptr, ct.len);
			uint64 val = FFINT_JOIN64(*(uint*)&k, *(uint*)&v);
			ffmap_add(&conf->fs.content_types_map, out.ptr, out.len, (void*)val);
			break;
		}

		case FFCONF_MORE:
		case FFCONF_ERROR:
		default:
			return;
		}
	}
}

void nml_http_file_uninit(struct nml_http_server_conf *conf)
{
	if (!conf) return;

	ffmap_free(&conf->fs.content_types_map);
	ffmem_free(conf->fs.content_types_data);
}

static void content_type(nml_http_sv_conn *c)
{
	ffstr x;
	int r = ffpath_splitname(c->file.buf.ptr, c->file.buf.len, NULL, &x);
	if (r <= 0 || ((char*)c->file.buf.ptr)[r] == '/' || x.len > 4)
		goto unknown;

	char lx[4];
	ffs_lower(lx, 4, x.ptr, x.len);
	void *val = ffmap_find(&c->conf->fs.content_types_map, lx, x.len, c);
	if (!val)
		goto unknown;

	uint lo = (uint64)val;
	ffstr v = range16_tostr((range16*)&lo, c->conf->fs.content_types_data);
	ffstr_setstr(&c->resp.content_type, &v);
	return;

unknown:
	ffstr_setz(&c->resp.content_type, "application/octet-stream");
}

static int f_open(nml_http_sv_conn *c)
{
	const char *fname = c->file.buf.ptr;
	if (HS_KCQ_ACTIVE(c))
		HS_DEBUG(c, "fffile_open: completed");

	if (FFFILE_NULL == (c->file.f = fffile_open_async(fname, FFFILE_READONLY | FFFILE_NOATIME, HS_KCQ_CTX(c)))) {
		if (fferr_notexist(fferr_last())) {
			HS_DEBUG(c, "fffile_open: %s: not found", fname);
			hs_response_err(c, HTTP_404_NOT_FOUND);
			return NMLR_DONE;
		} else if (fferr_last() == FFKCALL_EINPROGRESS) {
			HS_DEBUG(c, "fffile_open: %s: in progress", fname);
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "fffile_open: %s", fname);
		hs_response_err(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return NMLR_DONE;
	}

	return NMLR_FWD;
}

static int f_info(nml_http_sv_conn *c)
{
	if (HS_KCQ_ACTIVE(c))
		HS_DEBUG(c, "fffile_info: completed");

	if (fffile_info_async(c->file.f, &c->file.info, HS_KCQ_CTX(c))) {
		if (fferr_last() == FFKCALL_EINPROGRESS) {
			HS_DEBUG(c, "fffile_info: in progress");
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "fffile_info: %s", c->file.buf.ptr);
		hs_response_err(c, HTTP_403_FORBIDDEN);
		return NMLR_DONE;
	}

	if (handle_redirect(c, &c->file.info))
		return NMLR_DONE;
	if (mtime(c, &c->file.info))
		return NMLR_DONE;
	content_type(c);

	c->resp.content_length = fffileinfo_size(&c->file.info);
	hs_response(c, HTTP_200_OK);

	if (c->req_method_head) {
		c->resp_done = 1;
		return NMLR_DONE;
	}

	return NMLR_FWD;
}

static int hs_file_process(nml_http_sv_conn *c)
{
	ffssize r;
	switch (c->file.state) {
	case 0:
		if (NMLR_FWD != (r = f_open(c)))
			return r;
		c->file.state = 1;
		// fallthrough
	case 1:
		if (NMLR_FWD != (r = f_info(c)))
			return r;
		c->file.state = 2;
	}

	if (HS_KCQ_ACTIVE(c))
		HS_DEBUG(c, "fffile_read: completed");

	r = fffile_read_async(c->file.f, c->file.buf.ptr, c->file.buf.cap, HS_KCQ_CTX(c));
	if (r < 0) {
		if (fferr_last() == FFKCALL_EINPROGRESS) {
			HS_DEBUG(c, "fffile_read: in progress");
			return NMLR_ASYNC;
		}
		HS_SYSWARN(c, "fffile_read");
		return NMLR_ERR;
	} else if (r == 0) {
		c->resp_done = 1;
		return NMLR_DONE;
	}
	c->file.buf.len = r;
	ffstr_setstr(&c->output, &c->file.buf);
	return NMLR_FWD;
}

const nml_http_sv_component nml_http_sv_file = {
	hs_file_open, hs_file_close, hs_file_process,
	"file"
};
