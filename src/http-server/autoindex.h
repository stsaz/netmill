/** netmill: http-server: show directory contents
2022, Simon Zolin */

#include <http-server/client.h>
#include <ffsys/dirscan.h>

static int nml_autoindex_open(nml_http_sv_conn *c)
{
	if (c->resp_err
		|| *ffstr_last(&c->req.unescaped_path) != '/')
		return NMLF_SKIP;

	return NMLF_OPEN;
}

static void nml_autoindex_close(nml_http_sv_conn *c)
{
	ffvec_free(&c->autoindex.path);
	ffvec_free(&c->autoindex.buf);
}

static void autoindex_content(nml_http_sv_conn *c, ffdirscan *ds, ffvec *buf)
{
	ffvec namebuf = {};

	ffvec_addfmt(buf,
		"<html>\n"
		"<head>\n"
			"<meta charset=\"utf-8\">\n"
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
			"<title>Index of %S</title>\n"
		"</head>\n"
		"<body>\n"
			"<h1>Index of %S</h1>\n"
			"<pre>\n"
				"<a href=\"%S..\">..</a>\n"
		, &c->req.unescaped_path, &c->req.unescaped_path, &c->req.unescaped_path);

	ffvec_addstr(&namebuf, &c->req.unescaped_path);

	const char *fn;
	while ((fn = ffdirscan_next(ds))) {
		namebuf.len = c->req.unescaped_path.len;
		ffvec_add(&namebuf, fn, ffsz_len(fn)+1, 1);
		ffvec_addfmt(buf, "<a href=\"%s\">%s</a>\n"
			, namebuf.ptr, fn);
	}

	ffvec_addfmt(buf, "</pre></body></html>");
	ffvec_free(&namebuf);
}

static int nml_autoindex_process(nml_http_sv_conn *c)
{
	ffdirscan ds = {};

	if (0 == ffvec_addfmt(&c->autoindex.path, "%S%S%Z"
		, &c->conf->fs.www, &c->req.unescaped_path)) {
		cl_errlog(c, "no memory");
		cl_resp_status(c, HTTP_500_INTERNAL_SERVER_ERROR);
		goto end;
	}
	const char *path = c->autoindex.path.ptr;

	cl_dbglog(c, "dirscan: %s", path);
	if (0 != ffdirscan_open(&ds, path, 0)) {
		cl_syswarnlog(c, "ffdirscan_open: %s", path);
		int rc = HTTP_403_FORBIDDEN;
		if (fferr_notexist(fferr_last()))
			rc = HTTP_404_NOT_FOUND;
		cl_resp_status(c, rc);
		goto end;
	}

	autoindex_content(c, &ds, &c->autoindex.buf);

	c->resp.content_length = c->autoindex.buf.len;
	cl_resp_status_ok(c, HTTP_200_OK);
	ffstr_setstr(&c->output, &c->autoindex.buf);
	c->resp_done = 1;

end:
	ffdirscan_close(&ds);
	return NMLF_DONE;
}

const struct nml_filter nml_filter_autoindex = {
	(void*)nml_autoindex_open, (void*)nml_autoindex_close, (void*)nml_autoindex_process,
	"autoindex"
};
