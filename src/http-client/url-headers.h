/** netmill: executor: url: check response headers
2024, Simon Zolin */

#include <http-client/client.h>
#include <ffsys/std.h>

static int url_hdrs_open(nml_http_client *c)
{
	if (ux->conf.print_headers) {
		ffstr resp = range16_tostr(&c->response.whole, c->response.base);
		ffstdout_write(resp.ptr, resp.len);
	}

	if (ux->conf.headers_only)
		return NMLR_FIN;

	return NMLR_SKIP;
}

const nml_http_cl_component url_headers = {
	url_hdrs_open, NULL, NULL,
	"hdrs-check"
};
