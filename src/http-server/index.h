/** netmill: http-server: find an index document
2022, Simon Zolin */

#include <http-server/conn.h>
#include <ffsys/file.h>

static int hs_index_open(nml_http_sv_conn *c)
{
	if (c->resp_err || c->resp.code != 0
		|| *ffstr_last(&c->req.unescaped_path) != '/')
		return NMLR_SKIP;

	return NMLR_OPEN;
}

static void hs_index_close(nml_http_sv_conn *c)
{
}

/** ".../" -> ".../index.html" */
static int hs_index_process(nml_http_sv_conn *c)
{
	ffvec buf = {};
	if (0 == ffvec_addfmt(&buf, "%S%S%S%Z"
		, &c->conf->fs.www, &c->req.unescaped_path, &c->conf->fs.index_filename))
		goto nomem;
	const char *fn = buf.ptr;

	fffd fd;
	if (FFFILE_NULL == (fd = fffile_open(fn, FFFILE_READONLY | FFFILE_NOATIME))) {
		if (!fferr_notexist(fferr_last())) {
			HS_SYSWARN(c, "index: fffile_open: %s", fn);
		}
		ffvec_free(&buf);
		return NMLR_DONE;
	}
	HS_DEBUG(c, "index: found %s", fn);
	fffile_close(fd);
	ffvec_free(&buf);

	size_t cap = c->req.unescaped_path.len;
	if (0 == ffstr_growadd2(&c->req.unescaped_path, &cap, &c->conf->fs.index_filename))
		goto nomem;
	return NMLR_DONE;

nomem:
	HS_ERR(c, "no memory");
	hs_response_err(c, HTTP_500_INTERNAL_SERVER_ERROR);
	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_index = {
	hs_index_open, hs_index_close, hs_index_process,
	"index"
};
