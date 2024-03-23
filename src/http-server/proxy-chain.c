/** netmill: http-server: HTTP proxy outbound filters
2023, Simon Zolin */

#include <http-client/client.h>
#include <http-server/proxy-data.h>
#include <util/util.h>

extern void http_sv_proxy_wake(struct http_sv_proxy *p);

static int nml_http_proxy_input_open(nml_http_client *c) { return NMLF_OPEN; }

static int nml_http_proxy_input_process(nml_http_client *c)
{
	struct http_sv_proxy *p = c->conf->opaque;

	switch (p->req_state) {
	case PXREQ_1_READY:
		p->req_state = PXREQ_2_LOCKED;
		c->output = p->input;
		c->req_complete = p->req_complete;
		return (p->req_complete) ? NMLF_DONE : NMLF_FWD;

	case PXREQ_2_LOCKED:
		FF_ASSERT(c->chain_going_back);
		p->req_state = PXREQ_3_MORE;
		http_sv_proxy_wake(p);
		return NMLF_ASYNC;

	case PXREQ_0:
	case PXREQ_3_MORE:
		return NMLF_ASYNC;

	default:
		FF_ASSERT(0);
	}

	return NMLF_ERR;
}

const nml_http_cl_component nml_http_cl_proxy_input = {
	(void*)nml_http_proxy_input_open, NULL, (void*)nml_http_proxy_input_process,
	"proxy-input"
};


static int nml_http_proxy_output_open(nml_http_client *c)
{
	struct http_sv_proxy *p = c->conf->opaque;
	p->code = c->response.code;
	p->msg = range16_tostr(&c->response.msg, c->recv.buf.ptr);
	p->content_length = c->response.content_length;
	p->headers = range16_tostr(&c->response.headers, c->recv.buf.ptr);
	p->resp_status = 1;
	return NMLF_OPEN;
}

static int nml_http_proxy_output_process(nml_http_client *c)
{
	struct http_sv_proxy *p = c->conf->opaque;

	switch (p->resp_state) {
	case PXRESP_0:
		FF_ASSERT(!c->chain_going_back);
		p->resp_state = PXRESP_1_READY;
		p->resp_complete = c->resp_complete;
		p->output = c->input;
		http_sv_proxy_wake(p);
		return NMLF_ASYNC;

	case PXRESP_3_MORE:
		if (p->req_complete && p->resp_complete) {
			p->resp_state = PXRESP_4_DONE;
			return NMLF_FIN;
		}

		p->resp_state = PXRESP_0;
		return NMLF_BACK;

	default:
		FF_ASSERT(0);
	}

	return NMLF_ERR;
}

const nml_http_cl_component nml_http_cl_proxy_output = {
	(void*)nml_http_proxy_output_open, NULL, (void*)nml_http_proxy_output_process,
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
	//@ connection cache
	&nml_http_cl_connect,
	&nml_http_cl_request,
	&nml_http_cl_send,
	&nml_http_cl_recv,
	&nml_http_cl_response,
	&nml_http_cl_transfer,
	&nml_http_cl_proxy_output,
	NULL
};

/** CONNECT request processing filters */
const nml_http_cl_component* htsv_http_cl_tunnel_chain[] = {
	&nml_http_cl_proxy_input,
	&nml_http_cl_resolve,
	//@ connection cache
	&nml_http_cl_connect,
	&nml_http_cl_io,
	&nml_http_cl_proxy_output,
	NULL
};
