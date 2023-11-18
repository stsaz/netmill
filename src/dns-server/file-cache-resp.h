/** netmill: dns-server: write response to a file
2023, Simon Zolin */

static int dns_file_cache_resp_open(nml_dns_sv_conn *c)
{
	if (!c->upstream_resp)
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void dns_file_cache_resp_close(nml_dns_sv_conn *c)
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

static int dns_file_cache_resp_process(nml_dns_sv_conn *c)
{
	struct nml_dns_server_conf *conf = c->conf;
	if (!conf->filecache.dir || c->respbuf_cached.len) return NMLF_DONE;

	fcache_write(conf, &c->resp);
	return NMLF_DONE;
}

const nml_dns_component nml_dns_file_cache_resp = {
	dns_file_cache_resp_open, dns_file_cache_resp_close, dns_file_cache_resp_process,
	"file-cache-resp"
};
