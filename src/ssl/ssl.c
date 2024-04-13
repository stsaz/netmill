/** netmill: ssl
2023, Simon Zolin */

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

#include <ssl/htcl-send.h>
#include <ssl/htcl-receive.h>
#include <ssl/htsv-send.h>
#include <ssl/htsv-receive.h>

#include <ssl/htcl-handshake.h>
#include <ssl/htcl-request.h>
#include <ssl/htcl-response.h>
#include <ssl/htsv-handshake.h>
#include <ssl/htsv-request.h>
#include <ssl/htsv-response.h>

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
		{"htcl_handshake",	&nml_htcl_ssl_handshake},
		{"htcl_recv",		&nml_htcl_ssl_recv},
		{"htcl_req",		&nml_htcl_ssl_req},
		{"htcl_resp",		&nml_htcl_ssl_resp},
		{"htcl_send",		&nml_htcl_ssl_send},
		{"htsv_handshake",	&nml_htsv_ssl_handshake},
		{"htsv_recv",		&nml_htsv_ssl_recv},
		{"htsv_req",		&nml_htsv_ssl_req},
		{"htsv_resp",		&nml_htsv_ssl_resp},
		{"htsv_send",		&nml_htsv_ssl_send},
		{"ssl",				&nml_ssl_interface},
	};
	return nml_if_map_find(map, FF_COUNT(map), name);
}

NML_MOD_DEFINE(ssl);
