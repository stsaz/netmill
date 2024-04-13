/** netmill: dns-server: DoH upstream server: HTTPS outbound connection components
2023, Simon Zolin */

#include <http-client/client.h>
#include <dns-server/upstream-doh-data.h>
#include <util/ipaddr.h>

static int doh_resolve_open(nml_http_client *c)
{
	return NMLR_OPEN;
}

static void doh_resolve_close(nml_http_client *c)
{
	ffvec_free(&c->resolve.addrs);
}

static int doh_resolve_process(nml_http_client *c)
{
	struct nml_doh *d = c->conf->opaque;
	ffip6 *ip = ffvec_pushT(&c->resolve.addrs, ffip6);
	int r = nml_dns_hosts_find(d->dns_conf, c->conf->host, ip);
	if (!(r == 4 || r == 6)) {
		HC_ERR(c, "resolving '%S' via hosts file", &c->conf->host);
		return NMLR_ERR;
	}
	c->resolve.port = (c->conf->server_port) ? c->conf->server_port : 443;
	return NMLR_DONE;
}

const nml_http_cl_component nml_http_cl_doh_resolve = {
	doh_resolve_open, doh_resolve_close, doh_resolve_process,
	"doh-resolve"
};


static int doh_output_open(nml_http_client *c)
{
	struct nml_doh *d = c->conf->opaque;
	d->code = c->response.code;
	d->status = HC_RESPONSE_DATA(c, c->response.status);
	d->headers = HC_RESPONSE_DATA(c, c->response.headers);
	return NMLR_OPEN;
}

static int doh_output_process(nml_http_client *c)
{
	struct nml_doh *d = c->conf->opaque;
	FF_ASSERT(!c->chain_going_back);
	NML_ASSERT(c->resp_complete);
	d->body = c->input;
	d->resp_complete = 1;
	return NMLR_FIN;
}

const nml_http_cl_component nml_http_cl_doh_output = {
	doh_output_open, NULL, doh_output_process,
	"doh-output"
};
