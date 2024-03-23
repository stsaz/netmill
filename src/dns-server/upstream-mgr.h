/** netmill: dns-server: upstream servers
2023, Simon Zolin */

#include <dns-server/client.h>

struct upstream {
	const char *addr;
	void *ctx;
	void (*free)(void *p);
};

int nml_dns_upstreams_init(struct nml_dns_server_conf *conf)
{
	if (!conf->upstreams.upstreams.len)
		return 0;

	if (!ffvec_allocT(&conf->upstreams.servers, conf->upstreams.upstreams.len, struct upstream))
		return -1;

	const char **addr;
	FFSLICE_WALK(&conf->upstreams.upstreams, addr) {
		struct upstream *u = ffvec_zpushT(&conf->upstreams.servers, struct upstream);
		if (ffsz_matchz(*addr, "https://")) {
			u->ctx = nml_dns_doh_create(conf, *addr);
			u->free = nml_dns_doh_free;
		} else {
			u->ctx = nml_dns_udp_create(conf, *addr);
			u->free = nml_dns_udp_free;
		}
		if (!u->ctx)
			return -1;
		u->addr = *addr;
	}

	return 0;
}

void nml_dns_upstreams_uninit(struct nml_dns_server_conf *conf)
{
	struct upstream *u;
	FFSLICE_WALK(&conf->upstreams.servers, u) {
		u->free(u->ctx);
	}
	ffvec_free(&conf->upstreams.servers);
}

/** Get next server (round-robin) */
static struct upstream* ups_next_server(struct nml_dns_server_conf *conf)
{
	struct upstream *u = ffslice_itemT(&conf->upstreams.servers, conf->upstreams.iserver, struct upstream);
	conf->upstreams.iserver = (conf->upstreams.iserver + 1) % conf->upstreams.servers.len;
	return u;
}

static int dns_upstream_open(nml_dns_sv_conn *c)
{
	if (c->status)
		return NMLF_SKIP;

	c->upstream_attempts = c->conf->upstreams.resend_attempts + 1;
	return NMLF_OPEN;
}

static void dns_upstream_close(nml_dns_sv_conn *c)
{
}

/** Select server, send request, receive and parse response */
static int dns_upstream_process(nml_dns_sv_conn *c)
{
	for (;;) {
		if (!c->upstream_attempts)
			goto err;
		c->upstream_attempts--;

		struct upstream *u = ups_next_server(c->conf);
		c->upstream_active_ctx = u->ctx;
		c->upstream_doh = (u->free == nml_dns_doh_free);
		cl_dbglog(c, "using server '%s'", u->addr);
		return NMLF_FWD;
	}

err:
	c->rcode = FFDNS_SERVFAIL;
	c->status = "upstream-error";
	return NMLF_DONE;
}

const nml_dns_component nml_dns_upstream = {
	dns_upstream_open, dns_upstream_close, dns_upstream_process,
	"upstream-mgr"
};
