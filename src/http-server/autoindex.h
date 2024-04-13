/** netmill: http-server: show directory contents
2022, Simon Zolin */

#include <http-server/conn.h>
#include <ffsys/dirscan.h>

static int hs_autoindex_open(nml_http_sv_conn *c)
{
	if (c->resp_err
		|| *ffstr_last(&c->req.unescaped_path) != '/')
		return NMLR_SKIP;

	return NMLR_OPEN;
}

static void hs_autoindex_close(nml_http_sv_conn *c)
{
	ffvec_free(&c->autoindex.buf);
}

static int hs_autoindex_content(nml_http_sv_conn *c, ffdirscan *ds, ffvec *buf)
{
	uint r = 0;
	ffvec namebuf = {};

	r |= !ffvec_addfmt(buf,
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

	r |= !ffvec_addstr(&namebuf, &c->req.unescaped_path);

	const char *fn;
	while ((fn = ffdirscan_next(ds))) {
		namebuf.len = c->req.unescaped_path.len;
		r |= !ffvec_add(&namebuf, fn, ffsz_len(fn)+1, 1);
		r |= !ffvec_addfmt(buf, "<a href=\"%s\">%s</a>\n"
			, namebuf.ptr, fn);
	}

	r |= !ffvec_addfmt(buf, "</pre></body></html>");
	ffvec_free(&namebuf);
	return r;
}

static int hs_autoindex_process(nml_http_sv_conn *c)
{
	ffdirscan ds = {};

	ffvec buf = {};
	if (0 == ffvec_addfmt(&buf, "%S%S%Z"
		, &c->conf->fs.www, &c->req.unescaped_path))
		goto nomem;
	const char *path = buf.ptr;

	HS_DEBUG(c, "dirscan: %s", path);
	if (ffdirscan_open(&ds, path, 0)) {
		HS_SYSWARN(c, "ffdirscan_open: %s", path);
		int rc = HTTP_403_FORBIDDEN;
		if (fferr_notexist(fferr_last()))
			rc = HTTP_404_NOT_FOUND;
		hs_response_err(c, rc);
		goto end;
	}

	if (hs_autoindex_content(c, &ds, &c->autoindex.buf))
		goto nomem;

	c->resp.content_length = c->autoindex.buf.len;
	hs_response(c, HTTP_200_OK);
	ffstr_setstr(&c->output, &c->autoindex.buf);
	c->resp_done = 1;
	goto end;

nomem:
	HS_ERR(c, "no memory");
	hs_response_err(c, HTTP_500_INTERNAL_SERVER_ERROR);

end:
	ffvec_free(&buf);
	ffdirscan_close(&ds);
	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_autoindex = {
	hs_autoindex_open, hs_autoindex_close, hs_autoindex_process,
	"autoindex"
};
