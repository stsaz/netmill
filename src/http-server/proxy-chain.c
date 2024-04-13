/** netmill: http-server: HTTP proxy outbound request components
2023, Simon Zolin */

#include <http-client/client.h>
#include <http-server/proxy-data.h>
#include <util/util.h>

extern void hs_proxy_wake(struct http_sv_proxy *p);

static int hs_proxy_input_open(nml_http_client *c)
{
	return NMLR_OPEN;
}

static int hs_proxy_input_process(nml_http_client *c)
{
	struct http_sv_proxy *p = c->conf->opaque;

	switch (p->req_state) {
	case PXREQ_1_READY:
		p->req_state = PXREQ_2_LOCKED;
		c->output = p->input;
		c->req_complete = p->req_complete;
		return (p->req_complete) ? NMLR_DONE : NMLR_FWD;

	case PXREQ_2_LOCKED:
		FF_ASSERT(c->chain_going_back);
		p->req_state = PXREQ_3_MORE;
		hs_proxy_wake(p);
		return NMLR_ASYNC;

	case PXREQ_0:
	case PXREQ_3_MORE:
		return NMLR_ASYNC;

	default:
		FF_ASSERT(0);
	}

	return NMLR_ERR;
}

const nml_http_cl_component nml_http_cl_proxy_input = {
	hs_proxy_input_open, NULL, hs_proxy_input_process,
	"proxy-input"
};


static int hs_proxy_output_open(nml_http_client *c)
{
	struct http_sv_proxy *p = c->conf->opaque;
	p->code = c->response.code;
	p->msg = HC_RESPONSE_DATA(c, c->response.msg);
	p->content_length = c->response.content_length;
	p->headers = HC_RESPONSE_DATA(c, c->response.headers);
	p->resp_status = 1;
	return NMLR_OPEN;
}

static int hs_proxy_output_process(nml_http_client *c)
{
	struct http_sv_proxy *p = c->conf->opaque;

	switch (p->resp_state) {
	case PXRESP_0:
		FF_ASSERT(!c->chain_going_back);
		p->resp_state = PXRESP_1_READY;
		p->resp_complete = c->resp_complete;
		p->output = c->input;
		hs_proxy_wake(p);
		return NMLR_ASYNC;

	case PXRESP_3_MORE:
		if (p->req_complete && p->resp_complete) {
			p->resp_state = PXRESP_4_DONE;
			return NMLR_FIN;
		}

		p->resp_state = PXRESP_0;
		return NMLR_BACK;

	default:
		FF_ASSERT(0);
	}

	return NMLR_ERR;
}

const nml_http_cl_component nml_http_cl_proxy_output = {
	hs_proxy_output_open, NULL, hs_proxy_output_process,
	"proxy-output"
};

extern const nml_http_cl_component
	nml_http_cl_resolve,
	nml_http_cl_connection_cache,
	nml_http_cl_connect,
	nml_http_cl_io,
	nml_http_cl_send,
	nml_http_cl_recv,
	nml_http_cl_response,
	nml_http_cl_request,
	nml_http_cl_transfer;

const nml_http_cl_component* htsv_http_cl_chain[] = {
	&nml_http_cl_proxy_input,
	&nml_http_cl_resolve,
	// &nml_http_cl_connection_cache,
	&nml_http_cl_connect,
	&nml_http_cl_request,
	&nml_http_cl_send,
	&nml_http_cl_recv,
	&nml_http_cl_response,
	&nml_http_cl_transfer,
	&nml_http_cl_proxy_output,
	NULL
};

/** CONNECT request processing components */
const nml_http_cl_component* htsv_http_cl_tunnel_chain[] = {
	&nml_http_cl_proxy_input,
	&nml_http_cl_resolve,
	// &nml_http_cl_connection_cache,
	&nml_http_cl_connect,
	&nml_http_cl_io,
	&nml_http_cl_proxy_output,
	NULL
};
