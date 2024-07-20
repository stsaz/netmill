/** netmill: http-server: HTTP request processing chain
2023, Simon Zolin */

#include <http-server/request-receive.h>
#include <http-server/request.h>
#include <http-server/index.h>
#include <http-server/autoindex.h>
#include <http-server/file.h>
#include <http-server/error.h>
#include <http-server/transfer.h>
#include <http-server/response.h>
#include <http-server/response-send.h>
#include <http-server/access-log.h>
#include <http-server/keep-alive.h>

const nml_http_sv_component** nml_http_sv_chain(const nml_exe *exe, uint ssl)
{
	struct comp_name {
		char name[20];
		const void *iface;
	};

	static const struct comp_name plain_names[] = {
		{"", &nml_http_sv_receive},
		{"", &nml_http_sv_request},
		{"", &nml_http_sv_index},
		{"", &nml_http_sv_autoindex},
		{"", &nml_http_sv_file},
		{"", &nml_http_sv_error},
#if 1
		{"gzip.htsv_write", NULL},
#endif
		{"", &nml_http_sv_transfer},
		{"", &nml_http_sv_response},
		{"", &nml_http_sv_send},
		{"", &nml_http_sv_accesslog},
		{"", &nml_http_sv_keepalive},
	};

	static const struct comp_name ssl_names[] = {
		{"ssl.htsv_recv", NULL},
		{"ssl.htsv_handshake", NULL},
		{"ssl.htsv_send", NULL},
		{"ssl.htsv_recv", NULL},
		{"ssl.htsv_req", NULL},
		{"", &nml_http_sv_request},
		{"", &nml_http_sv_index},
		{"", &nml_http_sv_autoindex},
		{"", &nml_http_sv_file},
		{"", &nml_http_sv_error},
#if 1
		{"gzip.htsv_write", NULL},
#endif
		{"", &nml_http_sv_transfer},
		{"", &nml_http_sv_response},
		{"ssl.htsv_resp", NULL},
		{"ssl.htsv_send", NULL},
		{"", &nml_http_sv_accesslog},
		{"", &nml_http_sv_keepalive},
	};

	const struct comp_name *names = plain_names;
	uint n = FF_COUNT(plain_names);
	if (ssl) {
		names = ssl_names;
		n = FF_COUNT(ssl_names);
	}

	const nml_http_sv_component **c = ffmem_calloc(n + 1, sizeof(nml_http_sv_component*)), **pc = c;
	for (uint i = 0;  i < n;  i++) {
		if (names[i].iface)
			*pc++ = names[i].iface;
		// else
		// 	*pc++ = exe->provide(names[i].name);
	}
	*pc++ = NULL;
	return c;
}

const nml_http_sv_component* nml_http_server_chain_proxy[] = {
	&nml_http_sv_receive,
	&nml_http_sv_request,
	&nml_http_sv_proxy,
	&nml_http_sv_error,
	&nml_http_sv_transfer,
	&nml_http_sv_response,
	&nml_http_sv_send,
	&nml_http_sv_accesslog,
	&nml_http_sv_keepalive,
	NULL
};
