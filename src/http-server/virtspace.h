/** netmill: http-server: virtual directory
2023, Simon Zolin */

#include <http-server/client.h>
#include <ffbase/murmurhash3.h>

static int map_keyeq_func(void *opaque, const void *key, ffsize keylen, void *val);

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
		if (0 != ffmap_add_hash(m, hash, (void*)d))
			return -1;
	}
	return 0;
}

void nml_http_virtspace_uninit(struct nml_http_server_conf *conf)
{
	if (conf == NULL) return;

	ffmap_free(&conf->virtspace.map);
}

static int nml_vspc_open(nml_http_sv_conn *c)
{
	ffstr path = cl_req_hdr(c, c->req.path);
	ffstr method = cl_req_hdr(c, c->req.method);
	uint hash = hash_compute(path, method);
	if (NULL == (c->vspace.vdoc = ffmap_find_hash(&c->conf->virtspace.map, hash, c, 0, NULL)))
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void nml_vspc_close(nml_http_sv_conn *c)
{
}

static int map_keyeq_func(void *opaque, const void *key, ffsize keylen, void *val)
{
	const nml_http_sv_conn *c = key;
	const struct nml_http_virtdoc *d = val;
	ffstr path = cl_req_hdr(c, c->req.path);
	ffstr method = cl_req_hdr(c, c->req.method);
	if (ffstr_eqz(&path, d->path)
		&& ffstr_eqz(&method, d->method))
		return 1;
	return 0;
}

static int nml_vspc_process(nml_http_sv_conn *c)
{
	c->vspace.vdoc->handler(c);

	if (c->resp.content_length == ~0ULL) {
		cl_resp_status_ok(c, HTTP_200_OK);
		c->resp.content_length = 0;
		c->resp_done = 1;
	}
	return NMLF_DONE;
}

const struct nml_filter nml_filter_virtspace = {
	(void*)nml_vspc_open, (void*)nml_vspc_close, (void*)nml_vspc_process,
	"virtspace"
};
