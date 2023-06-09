/** netmill: http-server: HTTP proxy
2023, Simon Zolin */

#include <http-server/client.h>
#include <http-server/proxy-data.h>

extern const struct nml_filter *ocl_filters[];
extern const struct nml_filter *ocl_connect_filters[];

static void nml_proxy_on_complete(struct nml_proxy *p)
{
	p->signalled = 1;
	p->svconf->core.task(p->svconf->boss, &p->task, 1);
}

void nml_proxy_wake(struct nml_proxy *p)
{
	nml_http_sv_conn *c = p->ic;
	c->conveyor.cur = p->filter_index;
	p->svconf->core.task(p->svconf->boss, &p->task, 1);
}

static int nml_proxy_open(nml_http_sv_conn *c)
{
	if (c->resp_err) return NMLF_SKIP;

	struct nml_proxy *p = ffmem_new(struct nml_proxy);
	c->proxy = p;
	p->ic = c;
	p->svconf = c->conf;

	struct nml_http_client_conf *cc = &p->conf;
	nml_http_client_conf(NULL, cc);
	cc->opaque = p;

	cc->log_level = c->log_level;
	cc->log = c->log;
	cc->log_obj = c->log_obj;
	ffmem_copy(cc->id, c->id, sizeof(cc->id));

	nml_task_set(&p->task, (void*)c->conf->cl_wake, c);
	cc->wake = (void*)nml_proxy_on_complete;
	cc->wake_param = p;

	cc->core = c->conf->core;
	cc->boss = c->conf->boss;

	cc->host = cl_req_hdr(c, c->req.host);

	ffstr method = cl_req_hdr(c, c->req.method);
	if (ffstr_eqz(&method, "CONNECT")) {
		p->tunnel = 1;
		c->resp_connection_keepalive = 0;
		cc->filters = ocl_connect_filters;

	} else {
		cc->method = cl_req_hdr(c, c->req.method);
		cc->path = cl_req_hdr(c, c->req.path);
		cc->path.len = c->req.url.off + c->req.url.len - c->req.path.off;
		cc->headers = cl_req_hdr(c, c->req.full);
		ffstr_shift(&cc->headers, c->req.line.len + 1);
		if (cc->headers.ptr[0] == '\n')
			ffstr_shift(&cc->headers, 1);
		cc->filters = ocl_filters;
	}

	if (NULL == (p->cl = nml_http_client_new()))
		return NMLF_ERR;
	if (!!nml_http_client_conf(p->cl, cc))
		return NMLF_ERR;
	p->filter_index = c->conveyor.cur;
	return NMLF_OPEN;
}

static void nml_proxy_close(nml_http_sv_conn *c)
{
	struct nml_proxy *p = c->proxy;
	c->proxy = NULL;
	nml_http_client_free(p->cl);  p->cl = NULL;
	c->conf->core.task(c->conf->boss, &p->task, 0);
	ffmem_free(p);
}

static int nml_proxy_process(nml_http_sv_conn *c)
{
	struct nml_proxy *p = c->proxy;
	int in = 0, out = 0;

	cl_dbglog(c, "proxy filter state: %u|%u", p->req_state, p->resp_state);

	switch (p->resp_state) {
	case PXRESP_0:
		break;

	case PXRESP_1_READY:
		p->resp_state = PXRESP_2_LOCKED;
		if (p->resp_status) {
			p->resp_status = 0;
			if (p->tunnel) {
				cl_resp_status_ok(c, HTTP_200_OK);
			} else {
				c->resp.code = p->code;
				c->resp.msg = p->msg;
				c->resp.content_length = p->content_length;
				c->resp.headers = p->headers;
				c->resp_hdr_server_disable = 1;
			}
		}
		c->output = p->output;
		out = 'f';
		break;

	case PXRESP_2_LOCKED:
		FF_ASSERT(c->chain_going_back);
		p->resp_state = PXRESP_3_MORE;
		out = 'r';
		break;

	case PXRESP_4_DONE:
		c->resp_done = 1;
		return NMLF_DONE;
	}

	if (p->signalled) {
		if (c->send.transferred != 0)
			return NMLF_ERR;
		cl_resp_status(c, HTTP_502_BAD_GATEWAY);
		return NMLF_DONE;
	}

	switch (p->req_state) {
	case PXREQ_0:
		if (!c->chain_going_back) {
			p->req_state = PXREQ_1_READY;
			p->input = c->input;
			p->req_complete = (c->req_complete
				|| (p->tunnel && c->recv_fin));
		}
		break;

	case PXREQ_3_MORE:
		in = 'b';
		break;
	}

	if (out == 'f')
		return NMLF_FWD;
	else if (in == 'b') {
		p->req_state = PXREQ_0;
		return NMLF_BACK;
	}

	nml_http_client_run(p->cl);
	return NMLF_ASYNC;
}

const struct nml_filter nml_filter_proxy = {
	(void*)nml_proxy_open, (void*)nml_proxy_close, (void*)nml_proxy_process,
	"proxy"
};
