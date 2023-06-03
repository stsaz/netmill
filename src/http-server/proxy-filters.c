/** netmill: http-server: HTTP proxy outbound filters
2023, Simon Zolin */

#include <http-client/resolve.h>
#include <http-client/connect.h>
#include <http-client/io.h>
#include <http-client/request.h>
#include <http-client/request-send.h>
#include <http-client/response-receive.h>
#include <http-client/response.h>
#include <http-client/transfer.h>

#include <http-server/proxy-data.h>

extern void nml_proxy_wake(struct nml_proxy *p);

static int nml_http_proxy_input_open(nml_http_client *c) { return NMLF_OPEN; }

static int nml_http_proxy_input_process(nml_http_client *c)
{
	struct nml_proxy *p = c->conf->opaque;

	switch (p->req_state) {
	case PXREQ_1_READY:
		p->req_state = PXREQ_2_LOCKED;
		c->output = p->input;
		c->req_complete = p->req_complete;
		return (p->req_complete) ? NMLF_DONE : NMLF_FWD;

	case PXREQ_2_LOCKED:
		FF_ASSERT(c->chain_going_back);
		p->req_state = PXREQ_3_MORE;
		nml_proxy_wake(p);
		return NMLF_ASYNC;

	case PXREQ_0:
	case PXREQ_3_MORE:
		return NMLF_ASYNC;

	default:
		FF_ASSERT(0);
	}

	return NMLF_ERR;
}

const struct nml_filter nml_filter_http_cl_proxy_input = {
	(void*)nml_http_proxy_input_open, NULL, (void*)nml_http_proxy_input_process,
	"proxy-input"
};


static int nml_http_proxy_output_open(nml_http_client *c)
{
	struct nml_proxy *p = c->conf->opaque;
	p->code = c->response.code;
	p->msg = range16_tostr(&c->response.msg, c->recv.buf.ptr);
	p->content_length = c->response.content_length;
	p->headers = range16_tostr(&c->response.headers, c->recv.buf.ptr);
	p->resp_status = 1;
	return NMLF_OPEN;
}

static int nml_http_proxy_output_process(nml_http_client *c)
{
	struct nml_proxy *p = c->conf->opaque;

	switch (p->resp_state) {
	case PXRESP_0:
		FF_ASSERT(!c->chain_going_back);
		p->resp_state = PXRESP_1_READY;
		p->resp_complete = c->resp_complete;
		p->output = c->input;
		nml_proxy_wake(p);
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

const struct nml_filter nml_filter_http_cl_proxy_output = {
	(void*)nml_http_proxy_output_open, NULL, (void*)nml_http_proxy_output_process,
	"proxy-output"
};


const struct nml_filter *ocl_filters[] = {
	&nml_filter_http_cl_proxy_input,
	&nml_filter_resolve,
	&nml_filter_connect,
	&nml_filter_http_cl_request,
	&nml_filter_http_cl_send,
	&nml_filter_recv,
	&nml_filter_resp,
	&nml_filter_http_cl_transfer,
	&nml_filter_http_cl_proxy_output,
	NULL
};

/** CONNECT request processing filters */
const struct nml_filter *ocl_connect_filters[] = {
	&nml_filter_http_cl_proxy_input,
	&nml_filter_resolve,
	&nml_filter_connect,
	&nml_filter_io,
	&nml_filter_http_cl_proxy_output,
	NULL
};
