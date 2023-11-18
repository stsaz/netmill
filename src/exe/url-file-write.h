/** netmill: executor: url: process command-line arguments
2023, Simon Zolin */

#include <http-client/client.h>

static int filew_open(nml_http_client *c)
{
	if (ux->conf.print_headers) {
		ffstr resp = range16_tostr(&c->response.whole, c->response.base);
		ffstdout_write(resp.ptr, resp.len);
	}

	uint f = (ux->conf.force) ? FFFILE_CREATE : FFFILE_CREATENEW;
	if (FFFILE_NULL == (ux->fd = fffile_open(ux->conf.output, f | FFFILE_WRITEONLY))) {
		cl_syserrlog(c, "file open: %s", ux->conf.output);
		return NMLF_ERR;
	}

	if (fffile_trunc(ux->fd, 0)) {
		cl_syserrlog(c, "file truncate: %s", ux->conf.output);
		return NMLF_ERR;
	}
	return NMLF_OPEN;
}

static void filew_close(nml_http_client *c)
{
	if (ux->fd == FFFILE_NULL) return;

	if (fffile_close(ux->fd))
		cl_syserrlog(c, "file close: %s", ux->conf.output);
}

static int filew_process(nml_http_client *c)
{
	if (c->input.len != fffile_write(ux->fd, c->input.ptr, c->input.len)) {
		cl_syserrlog(c, "file write: %s", ux->conf.output);
		return NMLF_ERR;
	}
	if (c->resp_complete)
		return NMLF_FIN;
	return NMLF_BACK;
}

const nml_http_cl_component nml_http_cl_file_write = {
	(void*)filew_open, (void*)filew_close, (void*)filew_process,
	"file-write"
};
