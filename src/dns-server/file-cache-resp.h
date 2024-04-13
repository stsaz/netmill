/** netmill: dns-server: write response to a file
2023, Simon Zolin */

static int ds_fcache_resp_open(nml_dns_sv_conn *c)
{
	if (!c->upstream_resp)
		return NMLR_SKIP;
	return NMLR_OPEN;
}

static void ds_fcache_resp_close(nml_dns_sv_conn *c)
{
}

static fffd ds_fcache_create(struct nml_dns_server_conf *conf, char *fn)
{
	fffd fd;
	if (FFFILE_NULL == (fd = fffile_open(fn, FFFILE_CREATENEW | FFFILE_WRITEONLY))) {
		if (fferr_notexist(fferr_last())) {
			ffstr s = FFSTR_INITZ(fn);
			int slash = ffstr_rfindchar(&s, '/');
			FF_ASSERT(slash >= 0);
			fn[slash] = '\0';
			if (ffdir_make(fn) && !fferr_exist(fferr_last())) {
				DSC_SYSERR(conf, "ffdir_make: %s", fn);
				return FFFILE_NULL;
			}
			fn[slash] = '/';

			fd = fffile_open(fn, FFFILE_CREATENEW | FFFILE_WRITEONLY);
		}
		if (fd == FFFILE_NULL) {
			DSC_SYSERR(conf, "fffile_open: %s", fn);
			return FFFILE_NULL;
		}
	}
	return fd;
}

/** Add entries to a file "cache/L1/DOMAIN" */
static void ds_fcache_write(struct nml_dns_server_conf *conf, const struct dns_msg *msg)
{
	if (!conf->filecache.dir) return;

	char *fn_tmp = NULL, *fn = NULL;
	fffd fd = FFFILE_NULL;
	ffvec buf = {};

	if (!(fn_tmp = ds_fcache_fname(conf, &msg->q, 1)))
		goto end;

	if (FFFILE_NULL == (fd = ds_fcache_create(conf, fn_tmp)))
		goto end;

	if (NULL == ffvec_alloc(&buf, sizeof(struct ds_fcache_ent) + msg->data.len, 1))
		goto end;
	struct ds_fcache_ent *ce = buf.ptr;
	ffmem_zero_obj(ce);

	fftime now = conf->core.date(conf->boss, NULL);
	*(ffuint64*)ce->date = ffint_be_cpu64(now.sec);

	*(uint*)ce->ttl = (msg->ttl >= 0) ? ffint_be_cpu32(msg->ttl) : 0;

	buf.len = sizeof(struct ds_fcache_ent);
	ffvec_addstr(&buf, &msg->data);

	if (buf.len != (size_t)fffile_write(fd, buf.ptr, buf.len)) {
		DSC_SYSERR(conf, "fffile_write");
		goto end;
	}

	if (msg->ttl >= 0)
		now.sec += msg->ttl;
	now.sec -= FFTIME_1970_SECONDS;
	if (fffile_set_mtime(fd, &now))
		DSC_SYSERR(conf, "fffile_set_mtime");

	DSC_DEBUG(conf, "written %LB to file %s", msg->data.len, fn_tmp);
	fffile_close(fd);
	fd = FFFILE_NULL;

	fn = ffsz_dupn(fn_tmp, ffsz_len(fn_tmp) - FFS_LEN(".tmp"));
	if (fffile_rename(fn_tmp, fn)) {
		DSC_SYSERR(conf, "fffile_rename: %s", fn);
		goto end;
	}

end:
	if (fd != FFFILE_NULL)
		fffile_close(fd);
	ffmem_free(fn_tmp);
	ffmem_free(fn);
	ffvec_free(&buf);
}

static int ds_fcache_resp_process(nml_dns_sv_conn *c)
{
	struct nml_dns_server_conf *conf = c->conf;
	if (!conf->filecache.dir || c->respbuf_cached.len)
		return NMLR_DONE;

	ds_fcache_write(conf, &c->resp);
	return NMLR_DONE;
}

const nml_dns_component nml_dns_file_cache_resp = {
	ds_fcache_resp_open, ds_fcache_resp_close, ds_fcache_resp_process,
	"file-cache-resp"
};

#undef DSC_SYSERR
