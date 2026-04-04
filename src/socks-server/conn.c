/** netmill: SOCKS Server: connection processor
2026, Simon Zolin */

#include <socks-server/conn.h>
#include <util/ipaddr.h>
#include <ffsys/socket.h>
#include <ffsys/file.h>
#include <ffbase/vector.h>

static void sksv_conveyor_run(nml_socks_sv_conn *c);

static void sksv_destroy(nml_socks_sv_conn *c)
{
	SKSV_VERBOSE(c, "closing client connection");
	conveyor_close(&c->conveyor, c);
	c->conf->on_complete(c->conf->boss, c->sk, c->kev);
	ffmem_free(c);
}

/** Start processing the client */
void sksv_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_socks_server_conf *conf)
{
	nml_socks_sv_conn *c = ffmem_zalloc(sizeof(nml_socks_sv_conn));
	if (!c)
		return;
	c->sk = csock;
	c->conf = conf;

	c->log_level = conf->log_level;
	c->log = conf->log;
	c->log_obj = conf->log_obj;

	fftime t = c->conf->core.date(c->conf->boss, NULL);
	c->start_time_msec = fftime_to_msec(&t);

	if (!(c->kev = conf->core.kev_new(conf->boss))) {
		ffsock_close(csock);
		ffmem_free(c);
		return;
	}
	c->kev->rhandler = (void*)sksv_conveyor_run;
	c->kev->whandler = (void*)sksv_conveyor_run;
	c->kev->kcall.handler = (void*)sksv_conveyor_run;
	c->kev->kcall.param = c;

	c->conf->cl_wake = sksv_conveyor_run;
	c->conf->cl_destroy = sksv_destroy;

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
		SKSV_VERBOSE(c, "new client connection: %*s:%u"
			, (size_t)r, buf, c->peer_port);
	}

#ifdef FF_WIN
	if (sksv_async(c))
		return;
#endif

	conveyor_init(&c->conveyor, (const nml_component**)conf->chain);

#ifdef NML_ENABLE_LOG_EXTRA
	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG)) {
		c->conveyor.log = conf->log;
		c->conveyor.log_obj = conf->log_obj;
		c->conveyor.log_ctx = "socks-sv";
		c->conveyor.log_id = c->id;
	}
#endif

	sksv_conveyor_run(c);
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
static int sksv_conveyor_component_call(nml_socks_sv_conn *c, uint i)
{
	struct nml_conveyor *v = &c->conveyor;
	int r;

	if (NMLR_OPEN != (r = conveyor_open_once(v, i, c, nmlf_r_str)))
		return r;

	SKSV_EXTRALOG(c, "f#%u '%s': input:%L", i, v->comps[i]->name, c->input.len);
	r = v->process[i](c);
	SKSV_EXTRALOG(c, "  f#%u '%s': %s  output:%L", i, v->comps[i]->name, nmlf_r_str[r], c->output.len);
	return r;
}

static void sksv_conveyor_run(nml_socks_sv_conn *c)
{
	struct nml_conveyor *v = &c->conveyor;

	int i = v->cur, r;
	for (;;) {

		if (CONVEYOR_DONE_TEST(v, i)) {
			r = (!c->chain_going_back) ? NMLR_FWD : NMLR_BACK;
			if (r == NMLR_FWD)
				c->output = c->input;
		} else {
			r = sksv_conveyor_component_call(c, i);
		}

		switch (r) {
		case NMLR_SKIP:
			c->output = c->input;
			// fallthrough
		case NMLR_DONE:
			conveyor_done(v, i);
			// fallthrough

		case NMLR_FWD:
			if (conveyor_fwd(v, i, c->output.len)) {
				SKSV_ERR(c, "detected chain processing loop");
				FF_ASSERT(0);
				goto end;
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
				SKSV_ERR(c, "%s: the first filter asks for more input data", v->comps[i]->name);
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

		default:
			FF_ASSERT(0);
			goto end;
		}

		v->cur = i;
	}

end:
	sksv_destroy(c);
}
