/** netmill: SOCKS Server: request processing chain */

#include <socks-server/request-receive.h>
#include <socks-server/auth.h>
#include <socks-server/request.h>
#include <socks-server/resolve.h>
#include <socks-server/address-check.h>
#include <socks-server/connect.h>
#include <socks-server/response.h>
#include <socks-server/response-send.h>
#include <socks-server/io.h>
#include <socks-server/access-log.h>

const nml_socks_sv_component* nml_socks_server_chain[] = {
	&nml_sksv_receive,
	&nml_sksv_auth,
	&nml_sksv_send,

	&nml_sksv_request,
	&nml_sksv_resolve,
	&nml_sksv_addrchk,
	&nml_sksv_connect,
	&nml_sksv_io,
	&nml_sksv_response,
	&nml_sksv_send, // instance #2
	&nml_sksv_accesslog,
	NULL
};
