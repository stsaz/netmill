/** netmill: http-client: filters */

#include <http-client/resolve.h>
#include <http-client/connect.h>
#include <http-client/io.h>
#include <http-client/ssl.h>
#include <http-client/request.h>
#include <http-client/request-send.h>
#include <http-client/response-receive.h>
#include <http-client/response.h>
#include <http-client/transfer.h>
#include <http-client/redirect.h>

/*
// Plain HTTP client:
static const struct nml_filter *nml_http_cl_filters[] = {
	&nml_filter_resolve,
	&nml_filter_connect,
	&nml_filter_http_cl_request,
	&nml_filter_http_cl_send,
	&nml_filter_recv,
	&nml_filter_resp,
	&nml_filter_http_cl_transfer,
	&nml_filter_redir,
	NULL
};

// Secure HTTP client:
static const struct nml_filter *nml_http_cl_ssl_filters[] = {
	&nml_filter_resolve,
	&nml_filter_connect,
	&nml_filter_ssl_recv,
	&nml_filter_ssl_handshake,
	&nml_filter_ssl_send,
	&nml_filter_http_cl_request,
	&nml_filter_ssl_req,
	&nml_filter_ssl_send,
	&nml_filter_ssl_recv,
	&nml_filter_ssl_resp,
	&nml_filter_resp,
	&nml_filter_http_cl_transfer,
	&nml_filter_redir,
	NULL
};
*/
