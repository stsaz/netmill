/** netmill: http-server: find an index document
2022, Simon Zolin */

#include <http-server/client.h>
#include <FFOS/file.h>

static int nml_index_open(nml_http_sv_conn *c)
{
	if (c->resp_err || c->resp.code != 0
		|| *ffstr_last(&c->req.unescaped_path) != '/')
		return NMLF_SKIP;

	return NMLF_OPEN;
}

static void nml_index_close(nml_http_sv_conn *c)
{
	ffvec_free(&c->index.buf);
}

/** ".../" -> ".../index.html" */
static int nml_index_process(nml_http_sv_conn *c)
{
	if (0 == ffvec_addfmt(&c->index.buf, "%S%S%S%Z"
		, &c->conf->fs.www, &c->req.unescaped_path, &c->conf->fs.index_filename)) {
		cl_errlog(c, "no memory");
		cl_resp_status(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return NMLF_DONE;
	}
	const char *fn = c->index.buf.ptr;

	fffd fd;
	if (FFFILE_NULL == (fd = fffile_open(fn, FFFILE_READONLY | FFFILE_NOATIME))) {
		if (!fferr_notexist(fferr_last())) {
			cl_syswarnlog(c, "index: fffile_open: %s", fn);
		}
		return NMLF_DONE;
	}
	cl_dbglog(c, "index: found %s", fn);
	fffile_close(fd);
	ffvec_free(&c->index.buf);

	ffsize cap = c->req.unescaped_path.len;
	if (0 == ffstr_growadd2(&c->req.unescaped_path, &cap, &c->conf->fs.index_filename)) {
		cl_errlog(c, "no memory");
		cl_resp_status(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return NMLF_DONE;
	}
	return NMLF_DONE;
}

const struct nml_filter nml_filter_index = {
	(void*)nml_index_open, (void*)nml_index_close, (void*)nml_index_process,
	"index"
};
