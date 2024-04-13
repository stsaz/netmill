/** netmill: dns-server: DoH upstream server
2023, Simon Zolin */

#include <dns-server/upstream-doh-data.h>
#include <base64.h>

#define DOH_WARN(d, ...) \
	d->dns_conf->log(d->dns_conf->log_obj, NML_LOG_WARN, "upstream-doh", NULL, __VA_ARGS__)

#define DOH_INFO(d, ...) \
	d->dns_conf->log(d->dns_conf->log_obj, NML_LOG_INFO, "upstream-doh", NULL, __VA_ARGS__)

struct upstream_doh {
	const char *host;
	uint busy;
};

static void doh_on_complete(struct nml_doh *d)
{
	d->signalled = 1;
	d->dns_conf->core.task(d->dns_conf->boss, &d->task, 1);
}

static void doh_close(nml_dns_sv_conn *c)
{
	struct nml_doh *d = c->doh;
	c->doh = NULL;
	d->dns_conf->upstreams.hcif->free(d->htcl);
	d->htcl = NULL;
	dns_msg_destroy(&c->resp);
	ffvec_free(&c->respbuf);
	c->conf->core.task(c->conf->boss, &d->task, 0);
	ffmem_free(d);

	struct upstream_doh *u = c->upstream_active_ctx;
	u->busy = 0;
}

static ffstr doh_req_path(struct nml_doh *d)
{
	nml_dns_sv_conn *c = d->dns_conn;
	struct ffdns_hdr *h = (void*)c->reqbuf.ptr;
	*(ushort*)h->id = 0;

	ffstr req = {};
	req.ptr = d->buf;
	size_t cap = sizeof(d->buf);
	ffstr_addz(&req, cap, "/dns-query?dns=");
	int r = base64url_encode(req.ptr + req.len, cap - req.len, c->reqbuf.ptr, c->reqbuf.len);
	if (!r) {
		DOH_WARN(d, "too large input DNS request");
		return FFSTR_Z("");
	}
	req.len += r;
	return req;
}

static void* doh_http_cl_conf(struct upstream_doh *u, struct nml_doh *d)
{
	nml_dns_sv_conn *c = d->dns_conn;
	NML_ASSERT(c->conf->upstreams.hcif);
	NML_ASSERT(c->conf->upstreams.doh_ssl_ctx);
	struct nml_http_client_conf *hcc = &d->conf;
	d->dns_conf->upstreams.hcif->conf(NULL, hcc);
	hcc->opaque = d;

	hcc->log_level = c->conf->log_level;
	hcc->log = c->conf->log;
	hcc->log_obj = c->conf->log_obj;
	ffmem_copy(hcc->id, c->id, sizeof(hcc->id));

	nml_task_set(&d->task, (void*)c->conf->wake, c);
	hcc->wake = (void*)doh_on_complete;
	hcc->wake_param = d;

	hcc->core = c->conf->core;
	hcc->boss = c->conf->boss;

	hcc->ssl_ctx = c->conf->upstreams.doh_ssl_ctx;

	hcc->connect.cache = c->conf->upstreams.doh_connection_cache;
	hcc->connect.cif = c->conf->upstreams.cif;

	hcc->host = FFSTR_Z(u->host);
	hcc->path = doh_req_path(d);
	if (!hcc->path.len)
		return NULL;
	hcc->chain = c->conf->upstreams.doh_chain;
	return hcc;
}

void* nml_dns_doh_create(struct nml_dns_server_conf *conf, const char *addr)
{
	NML_ASSERT(ffsz_matchz(addr, "https://"));
	struct upstream_doh *u = ffmem_new(struct upstream_doh);
	u->host = addr + FFS_LEN("https://");
	return u;
}

void nml_dns_doh_free(void *p)
{
	struct upstream_doh *u = p;
	ffmem_free(u);
}

static void doh_retry(void *p)
{
	struct nml_doh *d = p;
	struct upstream_doh *u = d->dns_conn->upstream_active_ctx;
	if (0 != ffint_cmpxchg(&u->busy, 0, 1))
		return;
	d->dns_conf->core.timer(d->dns_conf->boss, &d->tmr, 0, NULL, NULL);
	d->dns_conf->core.task(d->dns_conf->boss, &d->task, 1);
	d->connection_busy = 0;
}

static int doh_open(nml_dns_sv_conn *c)
{
	if (c->status
		|| !c->upstream_doh)
		return NMLR_SKIP;

	struct upstream_doh *u = c->upstream_active_ctx;

	struct nml_doh *d = ffmem_new(struct nml_doh);
	c->doh = d;
	d->dns_conn = c;
	d->dns_conf = c->conf;

	struct nml_http_client_conf *cc = doh_http_cl_conf(u, d);
	if (!cc)
		goto err;
	if (!(d->htcl = d->dns_conf->upstreams.hcif->create()))
		goto err;
	if (d->dns_conf->upstreams.hcif->conf(d->htcl, cc))
		goto err;

	if (0 != ffint_cmpxchg(&u->busy, 0, 1)) {
		DS_DEBUG(c, "connection busy");
		c->conf->core.timer(c->conf->boss, &d->tmr, 50, doh_retry, d);
		d->connection_busy = 1;
		return NMLR_OPEN;
	}
	return NMLR_OPEN;

err:
	doh_close(c);
	return NMLR_ERR;
}

/** Parse response */
static int doh_response_parse(struct nml_doh *d, struct dns_msg *resp, ffstr data)
{
	int r;

	if (0 > (r = ffdns_header_read(&resp->h, data))) {
		DOH_WARN(d, "invalid header data");
		return -1;
	}

	if (!resp->h.response) {
		DOH_WARN(d, "not response");
		return -1;
	}

	uint off = r;
	if (0 > (r = ffdns_question_read(&resp->q, data))) {
		DOH_WARN(d, "invalid question data");
		return -1;
	}
	off += r;

	resp->ttl = -1;
	for (uint i = 0;  i != resp->h.answers;  i++) {
		ffdns_answer *a = ffvec_pushT(&resp->answers, ffdns_answer);
		ffmem_zero_obj(a);
		if (0 > (r = ffdns_answer_read(a, data, off))) {
			DOH_WARN(d, "invalid answer data");
			return -1;
		}
		off += r;
		resp->ttl = ffmin(resp->ttl, a->ttl);
	}

	ffstr_lower((ffstr*)&resp->q.name);
	return 0;
}

static void doh_log(struct nml_doh *d, nml_dns_sv_conn *c, const struct dns_msg *resp)
{
	fftime now = {};
	now = fftime_monotonic();
	fftime_sub(&now, &c->tstart);
	uint msec = fftime_to_msec(&now);
	DOH_INFO(d, "%u %S (%u) opcode:%d rcode:%d a:%u ns:%u ad:%u %LB %ums"
		, resp->q.type, &resp->q.name, resp->h.id, resp->h.opcode, resp->h.rcode
		, resp->h.answers, resp->h.nss, resp->h.additionals
		, resp->data.len
		, msec);
}

static void doh_response_prepare(nml_dns_sv_conn *c, const struct dns_msg *resp)
{
	ffvec_add2T(&c->respbuf, &resp->data, char);

	// rewrite header
	ffdns_header h = {
		.id = c->req.h.id,
		.response = 1,
		.rcode = resp->h.rcode,
		.recursion_available = 1,
		.questions = 1,
		.answers = resp->h.answers,
	};
	ffdns_header_write(c->respbuf.ptr, c->respbuf.cap, &h);
}

static int doh_process(nml_dns_sv_conn *c)
{
	struct nml_doh *d = c->doh;

	if (d->connection_busy)
		return NMLR_ASYNC;

	if (d->resp_complete) {

		if (d->code != 200) {
			DOH_WARN(d, "server response: %S", &d->status);
			goto err;
		}

		struct dns_msg resp = {};
		resp.data = d->body;

		if (0 > doh_response_parse(d, &resp, resp.data))
			return 0;

		doh_log(d, c, &resp);

		doh_response_prepare(c, &resp);
		c->resp = resp;
		c->status = "upstream-doh";
		c->upstream_resp = 1;
		return NMLR_DONE;
	}

	if (d->signalled) {
err:
		c->rcode = FFDNS_SERVFAIL;
		c->status = "upstream-doh-error";
		return NMLR_DONE;
	}

	d->dns_conf->upstreams.hcif->run(d->htcl);
	return NMLR_ASYNC;
}

const nml_dns_component nml_dns_upstream_doh = {
	doh_open, doh_close, doh_process,
	"upstream-doh"
};
