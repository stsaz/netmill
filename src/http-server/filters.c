/** netmill: http-server: HTTP processing filters
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

const struct nml_filter* nml_http_server_filters[] = {
	&nml_filter_receive,
	&nml_filter_request,
	&nml_filter_index,
	&nml_filter_autoindex,
	&nml_filter_file,
	&nml_filter_error,
	&nml_filter_transfer,
	&nml_filter_response,
	&nml_filter_send,
	&nml_filter_accesslog,
	&nml_filter_keepalive,
	NULL
};

extern const struct nml_filter nml_filter_proxy;

const struct nml_filter* nml_http_server_filters_proxy[] = {
	&nml_filter_receive,
	&nml_filter_request,
	&nml_filter_proxy,
	&nml_filter_error,
	&nml_filter_transfer,
	&nml_filter_response,
	&nml_filter_send,
	&nml_filter_accesslog,
	&nml_filter_keepalive,
	NULL
};
