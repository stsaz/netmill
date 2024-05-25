/** netmill: http-client: handle redirections
2023, Simon Zolin */

#include <http-client/client.h>

static int hc_redir_open(nml_http_client *c)
{
	if ((c->response.code == 301 || c->response.code == 302)
		&& c->response.location.len
		&& c->redirect_n != c->conf->max_redirect)
		return NMLR_OPEN;
	return NMLR_SKIP;
}

static void hc_redir_close(nml_http_client *c)
{
	ffmem_zero(&c->input, sizeof(nml_http_client) - FF_OFF(nml_http_client, input));
}

static int hc_redir_process(nml_http_client *c)
{
	ffstr loc = range16_tostr(&c->response.location, c->response.base);
	HC_VERBOSE(c, "redirect: %S", &loc);

	ffmem_free(c->redirect_location);
	if (!(c->redirect_location = ffsz_dupstr(&loc)))
		return NMLR_ERR;

	struct httpurl_parts p = {};
	httpurl_split(&p, FFSTR_Z(c->redirect_location));
	ffstr_set(&c->conf->host, p.host.ptr, p.host.len + p.port.len);
	ffstr_set(&c->conf->path, p.path.ptr, p.path.len + p.query.len);

	if (!c->conf->proxy_host.len
		&& p.port.len)
		c->conf->server_port = 0; // got new server port: invalidate user-specified port

	if (ffstr_eqz(&p.scheme, "http://")) {
		if (c->conf->ssl_ctx) {
			HC_ERR(c, "auto-switching to plain HTTP isn't supported yet");
			return NMLR_ERR;
		}

	} else if (ffstr_eqz(&p.scheme, "https://")) {
		if (!p.port.len)
			c->conf->server_port = 443; // 'resolve' defaults to 80: override it for https

		if (!c->conf->ssl_ctx) {
			HC_ERR(c, "auto-switching to secure HTTP isn't supported yet");
			return NMLR_ERR;
		}

	} else {
		HC_ERR(c, "redirected to an URL with unknown scheme %S", p.scheme);
		return NMLR_ERR;
	}

	c->redirect_n++;
	return NMLR_RESET;
}

const nml_http_cl_component nml_http_cl_redir = {
	hc_redir_open, hc_redir_close, hc_redir_process,
	"redirect"
};
