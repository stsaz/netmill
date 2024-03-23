/** netmill: ssl: SSL HTTP-client filters
2023, Simon Zolin */

#include <http-client/client.h>
#include <ssl/ssl.h>
#include <util/util.h>

const nml_exe *exe;

extern int cert_pem_create(const char *fn, uint pkey_bits, struct ffssl_cert_newinfo *ci);

static const struct nml_ssl_if nml_ssl_interface = {
	nml_ssl_init,
	nml_ssl_uninit,
	ffssl_conn_free,
	cert_pem_create,
};

#include <ssl/send.h>
#include <ssl/receive.h>

#include <ssl/handshake.h>
#include <ssl/request.h>
#include <ssl/response.h>

static void ssl_init(const nml_exe *x)
{
	exe = x;
}

static void ssl_destroy()
{
}

extern const struct nml_operation_if nml_op_cert;

static const void* ssl_provide(const char *name)
{
	static const struct nml_if_map map[] = {
		{"cert",			&nml_op_cert},
		{"htcl_handshake",	&nml_http_cl_ssl_handshake},
		{"htcl_recv",		&nml_http_cl_ssl_recv},
		{"htcl_req",		&nml_http_cl_ssl_req},
		{"htcl_resp",		&nml_http_cl_ssl_resp},
		{"htcl_send",		&nml_http_cl_ssl_send},
		{"ssl",				&nml_ssl_interface},
	};
	return nml_if_map_find(map, FF_COUNT(map), name);
}

NML_MOD_DEFINE(ssl);
