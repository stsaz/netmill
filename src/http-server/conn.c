/** netmill: http-server: connection processor
2022, Simon Zolin */

#include <http-server/conn.h>
#include <util/ipaddr.h>
#include <ffsys/socket.h>
#include <ffsys/file.h>
#include <ffbase/vector.h>

static void hs_conveyor_run(nml_http_sv_conn *c);

static void hs_destroy(nml_http_sv_conn *c)
{
	HS_VERBOSE(c, "closing client connection");
	conveyor_close(&c->conveyor, c);
	c->conf->on_complete(c->conf->boss, c->sk, c->kev);
	ffmem_free(c);
}

/** Start processing the client */
void hs_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_http_server_conf *conf)
{
	nml_http_sv_conn *c = ffmem_zalloc(sizeof(nml_http_sv_conn));
	if (!c)
		return;
	c->sk = csock;
	c->conf = conf;

	c->log_level = conf->log_level;
	c->log = conf->log;
	c->log_obj = conf->log_obj;

	if (!(c->kev = conf->core.kev_new(conf->boss))) {
		ffsock_close(csock);
		ffmem_free(c);
		return;
	}
	c->kev->rhandler = (void*)hs_conveyor_run;
	c->kev->whandler = (void*)hs_conveyor_run;
	c->kev->kcall.handler = (void*)hs_conveyor_run;
	c->kev->kcall.param = c;

	c->conf->cl_wake = hs_conveyor_run;
	c->conf->cl_destroy = hs_destroy;

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
		HS_VERBOSE(c, "new client connection: %*s:%u"
			, (size_t)r, buf, c->peer_port);
	}

#ifdef FF_WIN
	if (hs_async(c))
		return;
#endif

	conveyor_init(&c->conveyor, (const nml_component**)conf->chain);

#ifdef NML_ENABLE_LOG_EXTRA
	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG)) {
		c->conveyor.log = conf->log;
		c->conveyor.log_obj = conf->log_obj;
		c->conveyor.log_ctx = "http-sv";
		c->conveyor.log_id = c->id;
	}
#endif

	hs_conveyor_run(c);
}

static const char nmlf_r_str[][11] = {
	"NMLR_DONE",
	"NMLR_FWD",
	"NMLR_BACK",
	"NMLR_ASYNC",
	"NMLR_ERR",
	"NMLR_FIN",
	"NMLR_RESET",
	"NMLR_OPEN",
	"NMLR_SKIP",
};

/** Call the current component */
static int hs_conveyor_component_call(nml_http_sv_conn *c, uint i)
{
	struct nml_conveyor *v = &c->conveyor;
	const nml_http_sv_component *f = (nml_http_sv_component*)v->comps[i];
	int r;

	if (!CONVEYOR_OPENED_TEST(v, i)) {
		HS_EXTRALOG(c, "f#%u '%s': opening", i, f->name);
		r = f->open(c);
		(void)nmlf_r_str;
		HS_EXTRALOG(c, "  f#%u '%s': %s", i, f->name, nmlf_r_str[r]);
		if (r != NMLR_OPEN)
			return r;
		CONVEYOR_OPENED_SET(v, i);
	}

	HS_EXTRALOG(c, "f#%u '%s': input:%L", i, f->name, c->input.len);
	r = f->process(c);
	HS_EXTRALOG(c, "  f#%u '%s': %s  output:%L", i, f->name, nmlf_r_str[r], c->output.len);
	return r;
}

static void hs_conveyor_run(nml_http_sv_conn *c)
{
	struct nml_conveyor *v = &c->conveyor;

	int i = v->cur, r;
	for (;;) {

		if (CONVEYOR_DONE_TEST(v, i)) {
			r = (!c->chain_going_back) ? NMLR_FWD : NMLR_BACK;
			if (r == NMLR_FWD)
				c->output = c->input;
		} else {
			r = hs_conveyor_component_call(c, i);
		}

		switch (r) {
		case NMLR_SKIP:
			c->output = c->input;
			// fallthrough
		case NMLR_DONE:
			CONVEYOR_DONE_SET(v, i);
			v->active--;
			v->empty_data_counter = 0;
			HS_EXTRALOG(c, "chain: %u", v->active);
			// fallthrough

		case NMLR_FWD:
			if (!CONVEYOR_DONE_TEST(v, i)) {
				if (!c->output.len) {
					if (ff_unlikely(v->empty_data_counter > v->active * 2)) {
						HS_ERR(c, "detected chain processing loop");
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
			if (v->comps[i] != NULL)
				break;
			// fallthrough

		case NMLR_BACK:
			if (ff_unlikely(i == 0)) {
				HS_ERR(c, "%s: the first filter asks for more input data", v->comps[i]->name);
				FF_ASSERT(0);
				goto end;
			}
			ffstr_null(&c->input);
			c->chain_going_back = 1;
			i--;
			break;

		case NMLR_ASYNC:
			return;

		case NMLR_FIN:
		case NMLR_ERR:
			goto end;

		case NMLR_RESET:
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
	hs_destroy(c);
}
