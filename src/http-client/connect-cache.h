/** netmill: http-client: HTTP client connection cache bridge
2023, Simon Zolin */

#include <http-client/client.h>
#include <util/ssl.h>

struct http_cl_conn_cache_ent {
	u_char name[16+2];

	ffsock sk;
	void (*ssl_conn_free)(ffssl_conn *c);
	ffssl_conn *ssl_conn;
	nml_kevent *kev;

	void (*kev_free)(void *opaque, struct zzkevent *kev);
	void *opaque;
};

void nml_http_cl_conn_cache_destroy(void *opaque, ffstr name, ffstr data)
{
	struct http_cl_conn_cache_ent *ce = (void*)data.ptr;
	ffsock_close(ce->sk);
	if (ce->ssl_conn_free)
		ce->ssl_conn_free(ce->ssl_conn);
	ce->kev_free(ce->opaque, ce->kev);
}

static int hc_conn_cache_open(nml_http_client *c)
{
	if (!c->conf->connect.cache)
		return NMLR_SKIP;
	NML_ASSERT(c->conf->connect.cif);
	NML_ASSERT(!c->ssl.conn || c->conf->slif);
	return NMLR_OPEN;
}

static void hc_conn_cache_close(nml_http_client *c)
{
	if (c->sk == FFSOCK_NULL) return;

	if (!c->response.code) {
		HC_DEBUG(c, "no valid response from server");
		goto fail;
	}

	ffstr data = c->conf->connect.cif->reserve(c->conf->connect.cache, sizeof(struct http_cl_conn_cache_ent));
	if (!data.len)
		goto fail;
	struct http_cl_conn_cache_ent *ce = (void*)data.ptr;
	ffmem_copy(ce->name, c->connect.cache_name, sizeof(c->connect.cache_name));
	ce->sk = c->sk;
	if (c->conf->slif)
		ce->ssl_conn_free = c->conf->slif->conn_free;
	ce->ssl_conn = c->ssl.conn;
	ce->kev = c->kev;
	ce->kev_free = c->conf->core.kev_free;
	ce->opaque = c->conf->boss;
	ffstr name = FFSTR_INITN(ce->name, sizeof(ce->name));
	if (c->conf->connect.cif->add(c->conf->connect.cache, name, data))
		goto fail;

	c->sk = FFSOCK_NULL;
	c->ssl.conn = NULL;
	c->kev = NULL;
	return;

fail:
	if (!c->connection_from_cache) {
		HC_DEBUG(c, "connection will be closed by 'connect'");
		return;
	}

	// we own the socket
	c->conf->connect.cif->free(c->conf->connect.cache, c->connect.cache_data);
}

static int hc_conn_cache_process(nml_http_client *c)
{
	ffip6 ip = *ffslice_itemT(&c->resolve.addrs, c->connect.i_addr, ffip6);
	ffmem_copy(c->connect.cache_name, &ip, sizeof(ip));
	*(ushort*)(c->connect.cache_name+16) = ffint_be_cpu16(c->resolve.port);

	ffstr name = FFSTR_INITN(c->connect.cache_name, sizeof(c->connect.cache_name));
	ffstr data = c->conf->connect.cif->fetch(c->conf->connect.cache, name);
	if (!data.len)
		return NMLR_DONE;

	c->connect.cache_data = data;
	struct http_cl_conn_cache_ent *ce = (void*)data.ptr;
	c->sk = ce->sk;
	c->ssl.conn = ce->ssl_conn;
	c->kev = ce->kev;
	c->kev->obj = c;
	c->connection_from_cache = 1;
	HC_DEBUG(c, "connection from cache: socket:%L  kev:%p", (size_t)c->sk, c->kev);
	return NMLR_FWD;
}

const nml_http_cl_component nml_http_cl_connection_cache = {
	hc_conn_cache_open, hc_conn_cache_close, hc_conn_cache_process,
	"connect-cache"
};
