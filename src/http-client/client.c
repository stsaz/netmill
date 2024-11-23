/** netmill: http-client: outbound client
2023, Simon Zolin */

#include <http-client/client.h>

nml_http_client* nml_http_client_create()
{
	nml_http_client *c = ffmem_zalloc(sizeof(nml_http_client));
	return c;
}

void nml_http_client_free(nml_http_client *c)
{
	if (!c) return;

	HC_DEBUG(c, "closing outbound client context");
	conveyor_close(&c->conveyor, c);
	c->conf->core.kev_free(c->conf->boss, c->kev);
	ffmem_free(c->redirect_location);
	ffmem_free(c);
}

static void hc_conf_init(struct nml_http_client_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->connect_timeout_msec = 60*1000;
	conf->send_timeout_msec = 600*1000;
	conf->receive.timeout_msec = 600*1000;
	conf->receive.hdr_buf_size = 4*1024;
	conf->receive.max_buf = 64*1024;
	conf->receive.body_buf_size = 64*1024;
	conf->debug_data_dump_len = 80;
	conf->method = FFSTR_Z("GET");
}

void nml_http_client_run(nml_http_client *c);

static int hc_kev_create(nml_http_client *c)
{
	if (!(c->kev = c->conf->core.kev_new(c->conf->boss)))
		return -1;
	c->kev->rhandler = (void*)nml_http_client_run;
	c->kev->whandler = (void*)nml_http_client_run;
	c->kev->kcall.handler = (void*)nml_http_client_run;
	c->kev->kcall.param = c;
	return 0;
}

int nml_http_client_conf(nml_http_client *c, struct nml_http_client_conf *conf)
{
	if (!c) {
		hc_conf_init(conf);
		return 0;
	}

	c->conf = conf;
	c->log_level = conf->log_level;
	c->log_obj = conf->log_obj;
	c->log = conf->log;
	ffmem_copy(c->id, conf->id, sizeof(c->id));

	c->wake = (void*)nml_http_client_run;

	if (hc_kev_create(c))
		return -1;

	conveyor_init(&c->conveyor, (const nml_component**)conf->chain);

#ifdef NML_ENABLE_LOG_EXTRA
	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG)) {
		c->conveyor.log = conf->log;
		c->conveyor.log_obj = conf->log_obj;
		c->conveyor.log_ctx = "http-cl";
		c->conveyor.log_id = c->id;
	}
#endif

	return 0;
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
static int hc_conveyor_component_call(nml_http_client *c, uint i)
{
	struct nml_conveyor *v = &c->conveyor;
	const nml_http_cl_component *f = (nml_http_cl_component*)v->comps[i];
	int r;

	if (!CONVEYOR_OPENED_TEST(v, i)) {
		HC_EXTRALOG(c, "f#%u '%s': opening", i, f->name);
		r = f->open(c);
		(void)nmlf_r_str;
		HC_EXTRALOG(c, "  f#%u '%s': %s", i, f->name, nmlf_r_str[r]);
		if (r != NMLR_OPEN)
			return r;
		CONVEYOR_OPENED_SET(v, i);
	}

	HC_EXTRALOG(c, "f#%u '%s': input:%L", i, f->name, c->input.len);
	r = f->process(c);
	HC_EXTRALOG(c, "  f#%u '%s': %s  output:%L", i, f->name, nmlf_r_str[r], c->output.len);
	return r;
}

static void hc_signal_parent(nml_http_client *c)
{
	c->conf->wake(c->conf->wake_param);
}

void nml_http_client_run(nml_http_client *c)
{
	struct nml_conveyor *v = &c->conveyor;

	int i = v->cur, r;
	for (;;) {

		if (CONVEYOR_DONE_TEST(v, i)) {
			r = (!c->chain_going_back) ? NMLR_FWD : NMLR_BACK;
			if (r == NMLR_FWD)
				c->output = c->input;
		} else {
			r = hc_conveyor_component_call(c, i);
		}

		switch (r) {
		case NMLR_SKIP:
			c->output = c->input;
			// fallthrough
		case NMLR_DONE:
			CONVEYOR_DONE_SET(v, i);
			v->active--;
			v->empty_data_counter = 0;
			HC_EXTRALOG(c, "chain: %u", v->active);
			// fallthrough

		case NMLR_FWD:
			if (!CONVEYOR_DONE_TEST(v, i)) {
				if (!c->output.len) {
					if (v->empty_data_counter > v->active * 2) {
						HC_ERR(c, "detected chain processing loop");
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
			if (i == 0) {
				HC_ERR(c, "%s: the first filter asks for more input data", v->comps[i]->name);
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

			if (!c->kev)  {
				if (hc_kev_create(c)) // create new, because the old one was probably cached by 'connection-cache'
					goto end;
			}

			i = 0;
			break;

		default:
			FF_ASSERT(0);
			goto end;
		}

		v->cur = i;
	}

end:
	hc_signal_parent(c);
}

const struct nml_http_client_if nml_http_client_interface = {
	nml_http_client_create,
	nml_http_client_free,
	nml_http_client_conf,
	nml_http_client_run,
};
