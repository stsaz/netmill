/** netmill: executor: url: write data to file
2023, Simon Zolin */

#include <http-client/client.h>

static int url_filew_open(nml_http_client *c)
{
	uint f = (ux->conf.force) ? FFFILE_CREATE : FFFILE_CREATENEW;
	if (FFFILE_NULL == (ux->fd = fffile_open(ux->conf.output, f | FFFILE_WRITEONLY))) {
		HC_SYSERR(c, "file open: %s", ux->conf.output);
		return NMLR_ERR;
	}

	if (fffile_trunc(ux->fd, 0)) {
		HC_SYSERR(c, "file truncate: %s", ux->conf.output);
		return NMLR_ERR;
	}
	return NMLR_OPEN;
}

static void url_filew_close(nml_http_client *c)
{
	if (ux->fd == FFFILE_NULL) return;

	if (fffile_close(ux->fd))
		HC_SYSERR(c, "file close: %s", ux->conf.output);
}

static int url_filew_process(nml_http_client *c)
{
	if (c->input.len != fffile_write(ux->fd, c->input.ptr, c->input.len)) {
		HC_SYSERR(c, "file write: %s", ux->conf.output);
		return NMLR_ERR;
	}
	if (c->resp_complete)
		return NMLR_FIN;
	return NMLR_BACK;
}

const nml_http_cl_component nml_http_cl_file_write = {
	url_filew_open, url_filew_close, url_filew_process,
	"file-write"
};
