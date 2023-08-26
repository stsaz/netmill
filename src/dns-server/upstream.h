/** netmill: dns-server: upstream servers
2023, Simon Zolin */

#include <dns-server/client.h>
#include <util/kq.h>
#include <ffbase/mem-print.h>

#define ups_syserror(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_SYSERR, "upstream", u->idz, __VA_ARGS__)

#define ups_syswarning(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_SYSWARN, "upstream", u->idz, __VA_ARGS__)

#define ups_warning(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_WARN, "upstream", u->idz, __VA_ARGS__)

#define ups_info(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_INFO, "upstream", u->idz, __VA_ARGS__)

#define ups_debug(u, ...) \
do { \
	if (u->conf->log_level >= NML_LOG_DEBUG) \
		u->conf->log(u->conf->log_obj, NML_LOG_DEBUG, "upstream", u->idz, __VA_ARGS__); \
} while (0)

#define warning(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_WARN, "upstream", NULL, __VA_ARGS__)

#define debug(conf, ...) \
do { \
	if (conf->log_level >= NML_LOG_DEBUG) \
		conf->log(conf->log_obj, NML_LOG_DEBUG, "upstream", NULL, __VA_ARGS__); \
} while (0)

typedef struct upstream upstream;
struct upstream {
	struct nml_dns_server_conf *conf;
	struct zzkevent *kev;
	ffsockaddr addr;
	ffstr id;
	const char *idz;
	ffvec buf;
	ffsock sk;
	uint connected;
	nml_task task_read;
};


struct cl_key {
	ffbyte id[2];
	ffbyte type[2];
	ffbyte clas[2];
	ffbyte name[253+1];
	uint len;
};

static uint cl_key_init(struct cl_key *k, const struct dns_msg *m)
{
	ffmem_copy(k->id, &m->h.id, 2);
	ffmem_copy(k->type, &m->q.type, 2);
	ffmem_copy(k->clas, &m->q.clas, 2);
	ffmem_copy(k->name, m->q.name.ptr, m->q.name.len);
	k->name[m->q.name.len] = '\0';
	k->len = 2*3 + m->q.name.len + 1;
	return ffmap_hash(k, k->len);
}

static int ups_clients_keyeq(void *opaque, const void *key, ffsize keylen, void *val)
{
	const struct cl_key *k = key;
	const nml_dns_sv_conn *c = val;
	return !ffmem_cmp(k->id, &c->req.h.id, 2)
		&& !ffmem_cmp(k->type, &c->req.q.type, 2)
		&& !ffmem_cmp(k->clas, &c->req.q.clas, 2)
		&& !ffmem_cmp(k->name, c->req.q.name.ptr, c->req.q.name.len)
		&& k->name[c->req.q.name.len] == '\0';
}

static void ups_clients_add(struct nml_dns_server_conf *conf, struct nml_dns_sv_conn *c)
{
	struct cl_key k;
	uint hash = cl_key_init(&k, &c->req);
	ffmap_add_hash(&conf->upstreams.clients, hash, c);
	debug(conf, "added client [%L]", conf->upstreams.clients.len);
}

static struct nml_dns_sv_conn* ups_clients_fetch_rm(struct nml_dns_server_conf *conf, const struct dns_msg *m)
{
	struct cl_key k;
	uint hash = cl_key_init(&k, m);
	struct nml_dns_sv_conn *c = ffmap_find_hash(&conf->upstreams.clients, hash, &k, k.len, NULL);
	if (c == NULL)
		warning(conf, "no client with ID:%u name:%S", m->h.id, &m->q.name);

	if (0 == ffmap_rm_hash(&conf->upstreams.clients, hash, c))
		debug(conf, "removed client [%L]", conf->upstreams.clients.len);

	return c;
}


static void ups_read_input(upstream *u);

static int ups_sock_init(upstream *u)
{
	if (FFSOCK_NULL == (u->sk = ffsock_create_udp(AF_INET, FFSOCK_NONBLOCK))) {
		ups_syserror(u, "ffsock_create_udp");
		return -1;
	}

	ffsockaddr addr;
	ffsockaddr_set_ipv4(&addr, NULL, 0);
	if (ffsock_bind(u->sk, &addr)) {
		ups_syserror(u, "ffsock_bind");
		return -1;
	}

	u->kev = u->conf->core.kev_new(u->conf->boss);
	if (u->conf->core.kq_attach(u->conf->boss, u->sk, u->kev, u))
		return -1;
	u->kev->rhandler = (nml_func)ups_read_input;
	return 0;
}

int nml_dns_upstreams_init(struct nml_dns_server_conf *conf)
{
	if (!ffvec_allocT(&conf->upstreams.servers, conf->upstreams.upstreams.len, struct upstream))
		return -1;

	const char **addr;
	FFSLICE_WALK(&conf->upstreams.upstreams, addr) {
		upstream *u = ffvec_zpushT(&conf->upstreams.servers, struct upstream);
		u->sk = FFSOCK_NULL;
		u->conf = conf;
		ffstr_setz(&u->id, *addr);
		u->idz = *addr;
		if (!ffvec_alloc(&u->buf, 4*1024, 1))
			return -1;

		ffip6 ip;
		uint port = 53;
		int r = ffip_port_split(FFSTR_Z(*addr), &ip, &port);
		if (r < 0 || !(r & 1)) {
			return -1;
		}
		ffsockaddr_set_ipv4(&u->addr, ffip6_tov4(&ip), port);

		if (ups_sock_init(u))
			return -1;
	}

	ffmap_init(&conf->upstreams.clients, ups_clients_keyeq);
	return 0;
}

void nml_dns_upstreams_uninit(struct nml_dns_server_conf *conf)
{
	upstream *u;
	FFSLICE_WALK(&conf->upstreams.servers, u) {
		ffvec_free(&u->buf);
		ffsock_close(u->sk);
		conf->core.kev_free(conf->boss, u->kev);
	}
	ffvec_free(&conf->upstreams.servers);
	ffmap_free(&conf->upstreams.clients);
}

static void dns_conn_timeout(nml_dns_sv_conn *c)
{
	warning(c->conf, "%u %S: read timed out"
		, c->req.q.type, &c->req.q.name);
	c->conf->wake(c);
}

/** Send request */
static int ups_request(upstream *u, nml_dns_sv_conn *c)
{
	int r;
	int was_connected = u->connected;

	if (!u->connected) {
		r = ffsock_connect(u->sk, &u->addr);
		if (r < 0) {
			ups_syserror(u, "%S: ffsock_connect", &u->id);
			return -1;
		}
		u->connected = 1;
		nml_task_set(&u->task_read, (nml_func)ups_read_input, u);
		c->conf->core.task(c->conf->boss, &u->task_read, 1);
	}

	r = ffsock_send(u->sk, c->reqbuf.ptr, c->reqbuf.len, 0);
	if (r < 0) {
		if (was_connected) {
			ffsock_close(u->sk);  u->sk = FFSOCK_NULL;
			u->connected = 0;
			if (ups_sock_init(u))
				return -1;
			return ups_request(u, c);
		}
		ups_syserror(u, "%S: ffsock_send", &u->id);
		return -1;
	}
	c->conf->upstreams.out_data += r;
	c->conf->upstreams.out_reqs++;

	debug(c->conf, "%S: sent request %S (%u) %LB"
		, &u->id, &c->req.q.name, c->req.h.id, c->reqbuf.len);

	c->conf->core.timer(c->conf->boss, &c->ups_tmr_recv, -(int)c->conf->upstreams.read_timeout_msec, (void*)dns_conn_timeout, c);
	return 0;
}

/** Parse response */
static int ups_response_parse(upstream *u, struct dns_msg *resp, ffstr d)
{
	int r;

	if (0 > (r = ffdns_header_read(&resp->h, d))) {
		ups_warning(u, "invalid header data");
		return -1;
	}

	if (!resp->h.response) {
		ups_warning(u, "not response");
		return -1;
	}

	uint off = r;
	if (0 > (r = ffdns_question_read(&resp->q, d))) {
		ups_warning(u, "invalid question data");
		return -1;
	}
	off += r;

	resp->ttl = -1;
	for (uint i = 0;  i != resp->h.answers;  i++) {
		ffdns_answer *a = ffvec_pushT(&resp->answers, ffdns_answer);
		ffmem_zero_obj(a);
		if (0 > (r = ffdns_answer_read(a, d, off))) {
			ups_warning(u, "invalid answer data");
			return -1;
		}
		off += r;
		resp->ttl = ffmin(resp->ttl, a->ttl);
	}

	ffstr_lower((ffstr*)&resp->q.name);
	return 0;
}

static void ups_response_prepare(nml_dns_sv_conn *c, const struct dns_msg *resp)
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

/*
. read, parse response
. find the associated client; proceed with its filter chain */
static int ups_read_process(upstream *u)
{
	struct nml_dns_server_conf *conf = u->conf;
	struct dns_msg resp = {};
	int r = ffsock_recv_udp_async(u->sk, u->buf.ptr, u->buf.cap, &u->kev->rtask);
	if (r < 0) {
		if (fferr_last() != FFSOCK_EINPROGRESS)
			ups_syswarning(u, "ffsock_recv");
		return -1;
	}
	conf->upstreams.in_data += r;
	conf->upstreams.in_msgs++;
	ffstr_set(&resp.data, u->buf.ptr, r);
	ups_debug(u, "received %u bytes", r);

	if (conf->log_level >= NML_LOG_DEBUG && conf->debug_data_dump_len) {
		uint n = ffmin(resp.data.len, conf->debug_data_dump_len);
		ffstr ss = ffmem_alprint(resp.data.ptr, n, 0);
		ups_debug(u, "[%L]\n%S", n, &ss);
		ffstr_free(&ss);
	}

	if (0 > ups_response_parse(u, &resp, resp.data))
		return 0;

	nml_dns_sv_conn *c = ups_clients_fetch_rm(conf, &resp);

	fftime now = {};
	if (c != NULL) {
		now = fftime_monotonic();
		fftime_sub(&now, &c->tstart);
		conf->core.timer(conf->boss, &c->ups_tmr_recv, 0, NULL, 0);
	}
	uint msec = fftime_to_msec(&now);
	ups_info(u, "%u %S (%u) opcode:%d rcode:%d a:%u ns:%u ad:%u %LB %ums [total:%U/%U, %U/%U]"
		, resp.q.type, &resp.q.name, resp.h.id, resp.h.opcode, resp.h.rcode
		, resp.h.answers, resp.h.nss, resp.h.additionals
		, resp.data.len
		, msec
		, conf->upstreams.in_msgs, conf->upstreams.in_data
		, conf->upstreams.out_reqs, conf->upstreams.out_data);

	if (c == NULL) {
		goto end;
	}

	ups_response_prepare(c, &resp);
	c->resp = resp;
	c->status = "upstream";
	c->upstream_resp = 1;
	c->conf->wake(c);
	return 0;

end:
	dns_msg_destroy(&resp);
	return 0;
}

static void ups_read_input(upstream *u)
{
	for (;;) {
		if (ups_read_process(u))
			break;
	}
}

/** Get next server (round-robin) */
static struct upstream* ups_next_server(struct nml_dns_server_conf *conf)
{
	upstream *u = ffslice_itemT(&conf->upstreams.servers, conf->upstreams.iserver, struct upstream);
	conf->upstreams.iserver = (conf->upstreams.iserver + 1) % conf->upstreams.servers.len;
	return u;
}

static int nml_dns_upstream_open(nml_dns_sv_conn *c)
{
	if (c->status != NULL)
		return NMLF_SKIP;

	c->upstream_attempts = c->conf->upstreams.resend_attempts + 1;
	ups_clients_add(c->conf, c);
	return NMLF_OPEN;
}

static void nml_dns_upstream_close(nml_dns_sv_conn *c)
{
	dns_msg_destroy(&c->resp);
	ffvec_free(&c->respbuf);
}

/** Select server, send request, receive and parse response */
static int nml_dns_upstream_process(nml_dns_sv_conn *c)
{
	if (c->upstream_resp) {
		return NMLF_DONE;
	}

	for (;;) {
		if (c->upstream_attempts == 0)
			goto err;
		c->upstream_attempts--;

		upstream *u = ups_next_server(c->conf);
		if (ups_request(u, c))
			continue;
		return NMLF_ASYNC;
	}

err:
	c->rcode = FFDNS_SERVFAIL;
	c->status = "upstream-error";
	return NMLF_DONE;
}

const struct nml_filter nml_filter_dns_upstream = {
	(void*)nml_dns_upstream_open, (void*)nml_dns_upstream_close, (void*)nml_dns_upstream_process,
	"upstream"
};

#undef warning
#undef debug
