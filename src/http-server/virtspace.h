/** netmill: http-server: virtual directory
2023, Simon Zolin */

#include <http-server/conn.h>
#include <ffbase/murmurhash3.h>

static int map_keyeq_func(void *opaque, const void *key, size_t keylen, void *val);

static uint hash_compute(ffstr path, ffstr method)
{
	uint hash = murmurhash3(path.ptr, path.len, 0x12345678);
	return murmurhash3(method.ptr, method.len, hash);
}

int nml_http_virtspace_init(struct nml_http_server_conf *conf, const struct nml_http_virtdoc *docs)
{
	ffmap *m = &conf->virtspace.map;
	ffmap_init(m, map_keyeq_func);

	for (uint i = 0;  ;  i++) {
		const struct nml_http_virtdoc *d = &docs[i];
		if (d->path == NULL)
			break;

		uint hash = hash_compute(FFSTR_Z(d->path), FFSTR_Z(d->method));
		if (ffmap_add_hash(m, hash, (void*)d))
			return -1;
	}
	return 0;
}

void nml_http_virtspace_uninit(struct nml_http_server_conf *conf)
{
	if (!conf) return;

	ffmap_free(&conf->virtspace.map);
}

static int hs_vspc_open(nml_http_sv_conn *c)
{
	ffstr path = HS_REQUEST_DATA(c, c->req.path);
	ffstr method = HS_REQUEST_DATA(c, c->req.method);
	uint hash = hash_compute(path, method);
	if (!(c->vspace.vdoc = ffmap_find_hash(&c->conf->virtspace.map, hash, c, 0, NULL)))
		return NMLR_SKIP;
	return NMLR_OPEN;
}

static void hs_vspc_close(nml_http_sv_conn *c)
{
}

static int map_keyeq_func(void *opaque, const void *key, size_t keylen, void *val)
{
	const nml_http_sv_conn *c = key;
	const struct nml_http_virtdoc *d = val;
	ffstr path = HS_REQUEST_DATA(c, c->req.path);
	ffstr method = HS_REQUEST_DATA(c, c->req.method);
	if (ffstr_eqz(&path, d->path)
		&& ffstr_eqz(&method, d->method))
		return 1;
	return 0;
}

static int hs_vspc_process(nml_http_sv_conn *c)
{
	c->vspace.vdoc->handler(c);

	if (c->resp.content_length == ~0ULL) {
		hs_response(c, HTTP_200_OK);
		c->resp.content_length = 0;
		c->resp_done = 1;
	}
	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_virtspace = {
	hs_vspc_open, hs_vspc_close, hs_vspc_process,
	"virtspace"
};
