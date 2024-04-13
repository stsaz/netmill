/** netmill: dns-server: upstream servers
2023, Simon Zolin */

#include <dns-server/conn.h>

struct upstream {
	const char *addr;
	void *ctx;
	void (*free)(void *p);
};

int nml_dns_upstreams_init(struct nml_dns_server_conf *conf)
{
	if (!conf->upstreams.addresses.len)
		return 0;

	if (NULL == ffvec_allocT(&conf->upstreams.servers, conf->upstreams.addresses.len, struct upstream))
		return -1;

	const char **addr;
	FFSLICE_WALK(&conf->upstreams.addresses, addr) {
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
static struct upstream* ds_ups_next_server(struct nml_dns_server_conf *conf)
{
	struct upstream *u = ffslice_itemT(&conf->upstreams.servers, conf->upstreams.iserver, struct upstream);
	conf->upstreams.iserver = (conf->upstreams.iserver + 1) % conf->upstreams.servers.len;
	return u;
}

static int ds_upstream_open(nml_dns_sv_conn *c)
{
	if (c->status)
		return NMLR_SKIP;

	c->upstream_attempts = c->conf->upstreams.resend_attempts + 1;
	return NMLR_OPEN;
}

static void ds_upstream_close(nml_dns_sv_conn *c)
{
}

/** Select server, send request, receive and parse response */
static int ds_upstream_process(nml_dns_sv_conn *c)
{
	for (;;) {
		if (!c->upstream_attempts)
			goto err;
		c->upstream_attempts--;

		struct upstream *u = ds_ups_next_server(c->conf);
		c->upstream_active_ctx = u->ctx;
		c->upstream_doh = (u->free == nml_dns_doh_free);
		DS_DEBUG(c, "using server '%s'", u->addr);
		return NMLR_FWD;
	}

err:
	c->rcode = FFDNS_SERVFAIL;
	c->status = "upstream-error";
	return NMLR_DONE;
}

const nml_dns_component nml_dns_upstream = {
	ds_upstream_open, ds_upstream_close, ds_upstream_process,
	"upstream-mgr"
};
