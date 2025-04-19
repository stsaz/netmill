/** netmill: http-server: HTTP proxy
2023, Simon Zolin */

#include <http-server/conn.h>
#include <http-server/proxy-data.h>

extern const nml_http_cl_component* htsv_http_cl_chain[];
extern const nml_http_cl_component* htsv_http_cl_tunnel_chain[];

static void hs_proxy_on_complete(struct http_sv_proxy *p)
{
	p->signalled = 1;
	p->svconf->core.task(p->svconf->boss, &p->task, 1);
}

void hs_proxy_wake(struct http_sv_proxy *p)
{
	nml_http_sv_conn *c = p->ic;
	c->conveyor.cur = p->chain_pos;
	p->svconf->core.task(p->svconf->boss, &p->task, 1);
}

static int hs_proxy_open(nml_http_sv_conn *c)
{
	if (c->resp_err) return NMLR_SKIP;

	NML_ASSERT(c->conf->hcif);

	struct http_sv_proxy *p = ffmem_new(struct http_sv_proxy);
	c->proxy = p;
	p->ic = c;
	p->svconf = c->conf;

	struct nml_http_client_conf *cc = &p->conf;
	c->conf->hcif->conf(NULL, cc);
	cc->opaque = p;

	cc->log_level = c->log_level;
	cc->log = c->log;
	cc->log_obj = c->log_obj;
	ffmem_copy(cc->id, c->id, sizeof(cc->id));

	nml_task_set(&p->task, (void*)c->conf->cl_wake, c);
	cc->wake = (void*)hs_proxy_on_complete;
	cc->wake_param = p;

	cc->core = c->conf->core;
	cc->boss = c->conf->boss;

	cc->host = HS_REQUEST_DATA(c, c->req.host);

	ffstr method = HS_REQUEST_DATA(c, c->req.method);
	if (ffstr_eqz(&method, "CONNECT")) {
		p->tunnel = 1;
		c->req_no_chunked = 1;
		c->resp_connection_keepalive = 0;
		cc->chain = htsv_http_cl_tunnel_chain;

	} else {
		cc->method = HS_REQUEST_DATA(c, c->req.method);
		cc->path = HS_REQUEST_DATA(c, c->req.path);
		cc->path.len = c->req.url.off + c->req.url.len - c->req.path.off;
		cc->headers = HS_REQUEST_DATA(c, c->req.headers);
		cc->chain = htsv_http_cl_chain;
	}

	cc->connect.cache = c->conf->connection_cache;
	cc->connect.cif = c->conf->cif;

	if (!(p->cl = c->conf->hcif->create()))
		return NMLR_ERR;
	if (c->conf->hcif->conf(p->cl, cc))
		return NMLR_ERR;
	p->chain_pos = c->conveyor.cur;
	return NMLR_OPEN;
}

static void hs_proxy_close(nml_http_sv_conn *c)
{
	struct http_sv_proxy *p = c->proxy;
	c->proxy = NULL;
	c->conf->hcif->free(p->cl);
	p->cl = NULL;
	c->conf->core.task(c->conf->boss, &p->task, 0);
	ffmem_free(p);
}

static int hs_proxy_process(nml_http_sv_conn *c)
{
	struct http_sv_proxy *p = c->proxy;
	int in = 0, out = 0;

	HS_DEBUG(c, "proxy filter state: %u|%u", p->req_state, p->resp_state);

	switch (p->resp_state) {
	case PXRESP_0:
		break;

	case PXRESP_1_READY:
		p->resp_state = PXRESP_2_LOCKED;
		if (p->resp_status) {
			p->resp_status = 0;
			if (p->tunnel) {
				hs_response(c, HTTP_200_OK);
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
		return NMLR_DONE;
	}

	if (p->signalled) {
		if (c->send.transferred != 0)
			return NMLR_ERR;
		hs_response_err(c, HTTP_502_BAD_GATEWAY);
		return NMLR_DONE;
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
		return NMLR_FWD;
	else if (in == 'b') {
		p->req_state = PXREQ_0;
		return NMLR_BACK;
	}

	c->conf->hcif->run(p->cl);
	return NMLR_ASYNC;
}

const nml_http_sv_component nml_http_sv_proxy = {
	hs_proxy_open, hs_proxy_close, hs_proxy_process,
	"proxy"
};
