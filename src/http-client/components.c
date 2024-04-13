/** netmill: http-client: components */

#include <http-client/resolve.h>
#include <http-client/connect-cache.h>
#include <http-client/connect.h>
#include <http-client/io.h>
#include <http-client/request.h>
#include <http-client/request-send.h>
#include <http-client/response-receive.h>
#include <http-client/response.h>
#include <http-client/transfer.h>
#include <http-client/redirect.h>

/*
// Plain HTTP client
static const nml_http_cl_component* nml_http_cl_chain[] = {
	&nml_http_cl_resolve,
	&nml_http_cl_connect,
	&nml_http_cl_request,
	&nml_http_cl_send,
	&nml_http_cl_recv,
	&nml_http_cl_response,
	&nml_http_cl_transfer,
	&nml_http_cl_redir,
	NULL
};

// Secure HTTP client
static const nml_http_cl_component* nml_http_cl_ssl_chain[] = {
	&nml_http_cl_resolve,
	&nml_http_cl_connect,
	&nml_http_cl_ssl_recv,
	&nml_http_cl_ssl_handshake,
	&nml_http_cl_ssl_send,
	&nml_http_cl_request,
	&nml_http_cl_ssl_req,
	&nml_http_cl_ssl_send,
	&nml_http_cl_ssl_recv,
	&nml_http_cl_ssl_resp,
	&nml_http_cl_response,
	&nml_http_cl_transfer,
	&nml_http_cl_redir,
	NULL
};
*/
