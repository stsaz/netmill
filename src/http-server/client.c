/** netmill: http-server: inbound client
2022, Simon Zolin */

#include <http-server/client.h>
#include <util/ipaddr.h>
#include <FFOS/socket.h>
#include <FFOS/file.h>
#include <ffbase/vector.h>

static void cl_filters_run(nml_http_sv_conn *c);
static void cl_destroy(nml_http_sv_conn *c);

static void conveyor_log_init(struct nml_conveyor *v, const char *log_id, const struct nml_http_server_conf *conf)
{
#ifdef NML_ENABLE_LOG_EXTRA
	if (conf->log_level >= NML_LOG_DEBUG) {
		v->log = conf->log;
		v->log_obj = conf->log_obj;
		v->log_ctx = "http-sv";
		v->log_id = log_id;
	}
#endif
}

/** Start processing the client */
void cl_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_http_server_conf *conf)
{
	nml_http_sv_conn *c = ffmem_zalloc(sizeof(nml_http_sv_conn));
	if (c == NULL)
		return;
	c->sk = csock;
	c->conf = conf;

	c->log_level = conf->log_level;
	c->log = conf->log;
	c->log_obj = conf->log_obj;

	if (NULL == (c->kev = conf->core.kev_new(conf->boss))) {
		ffsock_close(csock);
		ffmem_free(c);
		return;
	}
	c->kev->rhandler = (void*)cl_filters_run;
	c->kev->whandler = (void*)cl_filters_run;
	c->kev->kcall.handler = (void*)cl_filters_run;
	c->kev->kcall.param = c;

	c->conf->cl_wake = cl_filters_run;
	c->conf->cl_destroy = cl_destroy;

	c->id[0] = '*';
	int r = ffs_fromint(conn_id, c->id+1, sizeof(c->id)-1, 0);
	c->id[r+1] = '\0';

	uint port = 0;
	ffslice ip = ffsockaddr_ip_port(peer, &port);
	if (ip.len == 4)
		ffip6_v4mapped_set((ffip6*)c->peer_ip, (ffip4*)ip.ptr);
	else
		ffmem_copy(c->peer_ip, ip.ptr, ip.len);
	c->peer_port = port;

	if (c->log_level >= NML_LOG_VERBOSE) {
		char buf[FFIP6_STRLEN];
		r = ffip46_tostr((void*)c->peer_ip, buf, sizeof(buf));
		cl_verblog(c, "new client connection: %*s:%u"
			, (ffsize)r, buf, c->peer_port);
	}

#ifdef FF_WIN
	if (0 != cl_async(c))
		return;
#endif

	conveyor_init(&c->conveyor, conf->filters);
	conveyor_log_init(&c->conveyor, c->id, c->conf);
	cl_filters_run(c);
}

static void cl_destroy(nml_http_sv_conn *c)
{
	cl_verblog(c, "closing client connection");
	conveyor_close(&c->conveyor, c);
	c->conf->on_complete(c->conf->boss, c->sk, c->kev);
	ffmem_free(c);
}

static const char nmlf_r_str[][11] = {
	"NMLF_DONE",
	"NMLF_FWD",
	"NMLF_BACK",
	"NMLF_ASYNC",
	"NMLF_ERR",
	"NMLF_FIN",
	"NMLF_RESET",
	"NMLF_OPEN",
	"NMLF_SKIP",
};

/** Call the current filter */
static int conveyor_filter_call(nml_http_sv_conn *c, uint i)
{
	struct nml_conveyor *v = &c->conveyor;
	const struct nml_filter *f = v->filters[i];
	int r;

	if (!v->rt[i].opened) {
		cl_extralog(c, "f#%u '%s': opening", i, f->name);
		r = f->open(c);
		(void)nmlf_r_str;
		cl_extralog(c, "  f#%u '%s': %s", i, f->name, nmlf_r_str[r]);
		if (r != NMLF_OPEN)
			return r;
		v->rt[i].opened = 1;
	}

	cl_extralog(c, "f#%u '%s': input:%L", i, f->name, c->input.len);
	r = f->process(c);
	cl_extralog(c, "  f#%u '%s': %s  output:%L", i, f->name, nmlf_r_str[r], c->output.len);
	return r;
}

static void cl_filters_run(nml_http_sv_conn *c)
{
	struct nml_conveyor *v = &c->conveyor;

	int i = v->cur, r;
	for (;;) {

		if (v->rt[i].done) {
			r = (!c->chain_going_back) ? NMLF_FWD : NMLF_BACK;
			if (r == NMLF_FWD)
				c->output = c->input;
		} else {
			r = conveyor_filter_call(c, i);
		}

		switch (r) {
		case NMLF_SKIP:
			c->output = c->input;
			// fallthrough
		case NMLF_DONE:
			v->rt[i].done = 1;
			v->active--;
			v->empty_data_counter = 0;
			cl_extralog(c, "chain: %u", v->active);
			// fallthrough

		case NMLF_FWD:
			if (!v->rt[i].done) {
				if (!c->output.len) {
					if (v->empty_data_counter > v->active * 2) {
						cl_errlog(c, "detected chain processing loop");
						FF_ASSERT(0);
						goto end;
					}
					v->empty_data_counter++;
				} else {
					v->empty_data_counter = 0;
				}
			}

			c->input = c->output;
			ffstr_null(&c->output);
			c->chain_going_back = 0;
			i++;
			if (v->filters[i] != NULL)
				break;
			// fallthrough

		case NMLF_BACK:
			if (i == 0) {
				cl_errlog(c, "the first filter asks for more input data");
				FF_ASSERT(0);
				goto end;
			}
			ffstr_null(&c->input);
			c->chain_going_back = 1;
			i--;
			break;

		case NMLF_ASYNC:
			return;

		case NMLF_FIN:
		case NMLF_ERR:
			goto end;

		case NMLF_RESET:
			c->chain_reset = 1;
			conveyor_close(&c->conveyor, c);
			conveyor_reset(&c->conveyor);
			c->chain_reset = 0;
			c->chain_going_back = 0;
			c->input.len = 0;
			i = 0;
			break;

		default:
			FF_ASSERT(0);
			goto end;
		}

		v->cur = i;
	}

end:
	cl_destroy(c);
}
