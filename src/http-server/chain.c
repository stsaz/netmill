/** netmill: http-server: HTTP processing chain
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

const nml_http_sv_component* nml_http_server_chain[] = {
	&nml_http_sv_receive,
	&nml_http_sv_request,
	&nml_http_sv_index,
	&nml_http_sv_autoindex,
	&nml_http_sv_file,
	&nml_http_sv_error,
	&nml_http_sv_transfer,
	&nml_http_sv_response,
	&nml_http_sv_send,
	&nml_http_sv_accesslog,
	&nml_http_sv_keepalive,
	NULL
};

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
