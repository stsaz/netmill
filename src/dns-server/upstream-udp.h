/** netmill: dns-server: UDP upstream server
2023, Simon Zolin */

#include <dns-server/client.h>
#include <util/kq.h>
#include <ffbase/mem-print.h>

#define ups_syserror(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_SYSERR, "upstream-udp", u->idz, __VA_ARGS__)

#define ups_error(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_ERR, "upstream-udp", u->idz, __VA_ARGS__)

#define ups_syswarning(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_SYSWARN, "upstream-udp", u->idz, __VA_ARGS__)

#define ups_warning(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_WARN, "upstream-udp", u->idz, __VA_ARGS__)

#define ups_info(u, ...) \
	u->conf->log(u->conf->log_obj, NML_LOG_INFO, "upstream-udp", u->idz, __VA_ARGS__)

#define ups_debug(u, ...) \
do { \
	if (u->conf->log_level >= NML_LOG_DEBUG) \
		u->conf->log(u->conf->log_obj, NML_LOG_DEBUG, "upstream-udp", u->idz, __VA_ARGS__); \
} while (0)

struct dns_udp {
	struct nml_dns_server_conf *conf;
	struct zzkevent *kev;
	ffsockaddr	addr;
	ffstr		id;
	const char *idz;
	ffvec		buf;
	ffsock		sk;
	uint		connected;
	nml_task	task_read;
	ffmap		clients; // req.ID + req.Q -> nml_dns_sv_conn*
};


struct cl_key {
	u_char	id[2];
	u_char	type[2];
	u_char	clas[2];
	u_char	name[253+1];
	uint	len;
};

/** Create key from DNS message */
static uint cl_key_init(struct cl_key *k, const struct dns_msg *m)
{
	*(ushort*)k->id = ffint_be_cpu16(m->h.id);
	*(ushort*)k->type = ffint_be_cpu16(m->q.type);
	*(ushort*)k->clas = ffint_be_cpu16(m->q.clas);
	ffmem_copy(k->name, m->q.name.ptr, m->q.name.len);
	k->name[m->q.name.len] = '\0';
	k->len = 2*3 + m->q.name.len + 1;
	return ffmap_hash(k, k->len);
}

static int dns_udp_clients_keyeq(void *opaque, const void *key, ffsize keylen, void *val)
{
	const struct cl_key *k = key;
	const nml_dns_sv_conn *c = val;
	return ffint_be_cpu16_ptr(k->id) == c->req.h.id
		&& ffint_be_cpu16_ptr(k->type) == c->req.q.type
		&& ffint_be_cpu16_ptr(k->clas) == c->req.q.clas
		&& !ffmem_cmp(k->name, c->req.q.name.ptr, c->req.q.name.len)
		&& k->name[c->req.q.name.len] == '\0';
}

static void dns_udp_clients_add(struct dns_udp *u, struct nml_dns_server_conf *conf, struct nml_dns_sv_conn *c)
{
	struct cl_key k;
	uint hash = cl_key_init(&k, &c->req);
	ffmap_add_hash(&u->clients, hash, c);
	ups_debug(u, "added client [%L]", u->clients.len);
}

static struct nml_dns_sv_conn* dns_udp_clients_fetch_rm(struct dns_udp *u, struct nml_dns_server_conf *conf, const struct dns_msg *m)
{
	struct cl_key k;
	uint hash = cl_key_init(&k, m);
	struct nml_dns_sv_conn *c = ffmap_find_hash(&u->clients, hash, &k, k.len, NULL);
	if (c == NULL)
		ups_warning(u, "no client with ID:%u name:%S", m->h.id, &m->q.name);

	if (!ffmap_rm_hash(&u->clients, hash, c))
		ups_debug(u, "removed client [%L]", u->clients.len);

	return c;
}


void* nml_dns_udp_create(struct nml_dns_server_conf *conf, const char *addr)
{
	struct dns_udp *u = ffmem_new(struct dns_udp);
	u->sk = FFSOCK_NULL;
	u->conf = conf;
	ffstr_setz(&u->id, addr);
	u->idz = addr;

	ffip6 ip;
	uint port = 53;
	int r = ffip_port_split(FFSTR_Z(addr), &ip, &port);
	if (r < 0 || !(r & 1)) {
		ups_error(u, "invalid address: %s", addr);
		return NULL;
	}
	if (ffip6_tov4(&ip))
		ffsockaddr_set_ipv4(&u->addr, ffip6_tov4(&ip), port);
	else
		ffsockaddr_set_ipv6(&u->addr, &ip, port);

	ffmap_init(&u->clients, dns_udp_clients_keyeq);
	return u;
}

void nml_dns_udp_free(void *p)
{
	struct dns_udp *u = p;
	ffvec_free(&u->buf);
	ffsock_close(u->sk);
	u->conf->core.kev_free(u->conf->boss, u->kev);
	ffmap_free(&u->clients);
	ffmem_free(u);
}

static void ups_read_expired(nml_dns_sv_conn *c)
{
	struct dns_udp *u = c->upstream_active_ctx;
	c->upstream_timeout = 1;
	ups_warning(u, "%u %S: read timed out"
		, c->req.q.type, &c->req.q.name);
	c->conf->wake(c);
}

static void ups_read_input(struct dns_udp *u);

static inline int ffsockaddr_family(ffsockaddr *a) { return a->ip4.sin_family; }

static int ups_sock_init(struct dns_udp *u)
{
	if (FFSOCK_NULL == (u->sk = ffsock_create_udp(ffsockaddr_family(&u->addr), FFSOCK_NONBLOCK))) {
		ups_syserror(u, "ffsock_create_udp");
		return -1;
	}

	ffsockaddr addr;
	if (ffsockaddr_family(&u->addr) == AF_INET)
		ffsockaddr_set_ipv4(&addr, NULL, 0);
	else
		ffsockaddr_set_ipv6(&addr, NULL, 0);
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

/** Send request */
static int ups_request(struct dns_udp *u, nml_dns_sv_conn *c)
{
	int r;
	int was_connected = u->connected;

	if (!u->connected) {
		if (!u->buf.cap && !ffvec_alloc(&u->buf, 4*1024, 1))
			return -1;

		if (ups_sock_init(u))
			return -1;

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
			return ups_request(u, c);
		}
		ups_syserror(u, "%S: ffsock_send", &u->id);
		return -1;
	}
	c->conf->upstreams.out_data += r;
	c->conf->upstreams.out_reqs++;

	ups_debug(u, "%S: sent request %S (%u) %LB"
		, &u->id, &c->req.q.name, c->req.h.id, c->reqbuf.len);

	c->conf->core.timer(c->conf->boss, &c->ups_tmr_recv, -(int)c->conf->upstreams.read_timeout_msec, (void*)ups_read_expired, c);
	return 0;
}

/** Parse response */
static int ups_response_parse(struct dns_udp *u, struct dns_msg *resp, ffstr data)
{
	int r;

	if (0 > (r = ffdns_header_read(&resp->h, data))) {
		ups_warning(u, "invalid header data");
		return -1;
	}

	if (!resp->h.response) {
		ups_warning(u, "not response");
		return -1;
	}

	uint off = r;
	if (0 > (r = ffdns_question_read(&resp->q, data))) {
		ups_warning(u, "invalid question data");
		return -1;
	}
	off += r;

	resp->ttl = -1;
	for (uint i = 0;  i != resp->h.answers;  i++) {
		ffdns_answer *a = ffvec_pushT(&resp->answers, ffdns_answer);
		ffmem_zero_obj(a);
		if (0 > (r = ffdns_answer_read(a, data, off))) {
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

static void ups_log(struct dns_udp *u, nml_dns_sv_conn *c, const struct dns_msg *resp)
{
	struct nml_dns_server_conf *conf = u->conf;
	fftime now = {};
	if (c != NULL) {
		now = fftime_monotonic();
		fftime_sub(&now, &c->tstart);
	}
	uint msec = fftime_to_msec(&now);
	ups_info(u, "%u %S (%u) opcode:%d rcode:%d a:%u ns:%u ad:%u %LB %ums [total:%U/%U, %U/%U]"
		, resp->q.type, &resp->q.name, resp->h.id, resp->h.opcode, resp->h.rcode
		, resp->h.answers, resp->h.nss, resp->h.additionals
		, resp->data.len
		, msec
		, conf->upstreams.in_msgs, conf->upstreams.in_data
		, conf->upstreams.out_reqs, conf->upstreams.out_data);
}

/*
. read, parse response
. find the associated client; proceed with its filter chain */
static int ups_read_process(struct dns_udp *u)
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

	nml_dns_sv_conn *c = dns_udp_clients_fetch_rm(u, conf, &resp);

	ups_log(u, c, &resp);

	if (c == NULL) {
		goto end;
	}

	conf->core.timer(conf->boss, &c->ups_tmr_recv, 0, NULL, 0);

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

static void ups_read_input(struct dns_udp *u)
{
	for (;;) {
		if (ups_read_process(u))
			break;
	}
}

static int dns_udp_open(nml_dns_sv_conn *c)
{
	if (c->status)
		return NMLF_SKIP;

	struct dns_udp *u = c->upstream_active_ctx;
	dns_udp_clients_add(u, c->conf, c);
	return NMLF_OPEN;
}

static void dns_udp_close(nml_dns_sv_conn *c)
{
	dns_msg_destroy(&c->resp);
	ffvec_free(&c->respbuf);
}

static int dns_udp_process(nml_dns_sv_conn *c)
{
	if (c->status) {
		return NMLF_DONE;
	}

	if (c->upstream_timeout) {
		return NMLF_BACK;
	}

	struct dns_udp *u = c->upstream_active_ctx;
	if (ups_request(u, c)) {
		return NMLF_BACK;
	}

	return NMLF_ASYNC;
}

const nml_dns_component nml_dns_upstream_udp = {
	dns_udp_open, dns_udp_close, dns_udp_process,
	"upstream-udp"
};
