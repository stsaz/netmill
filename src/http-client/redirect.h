/** netmill: http-client: handle redirections
2023, Simon Zolin */

#include <http-client/client.h>

static int nml_redir_open(nml_http_client *c)
{
	if ((c->response.code == 301 || c->response.code == 302)
		&& c->response.location.len
		&& c->redirect_n != c->conf->max_redirect)
		return NMLF_OPEN;
	return NMLF_SKIP;
}

static void nml_redir_close(nml_http_client *c)
{
	struct httpurl_parts p = {};
	httpurl_split(&p, FFSTR_Z(c->redirect_location));
	ffstr_set(&c->conf->host, p.host.ptr, p.host.len + p.port.len);
	c->conf->path = p.path;

	ffmem_zero(&c->input, sizeof(nml_http_client) - FF_OFF(nml_http_client, input));
}

static int nml_redir_process(nml_http_client *c)
{
	ffstr loc = range16_tostr(&c->response.location, c->recv.buf.ptr);
	cl_verblog(c, "redirect: %S", &loc);

	ffmem_free(c->redirect_location);
	if (NULL == (c->redirect_location = ffsz_dupstr(&loc)))
		return NMLF_ERR;

	c->redirect_n++;
	return NMLF_RESET;
}

const struct nml_filter nml_filter_redir = {
	(void*)nml_redir_open, (void*)nml_redir_close, (void*)nml_redir_process,
	"redirect"
};
