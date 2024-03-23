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
	cl_dbglog(c, "closing outbound client context");
	conveyor_close(&c->conveyor, c);
	c->conf->core.kev_free(c->conf->boss, c->kev);
	ffmem_free(c->redirect_location);
	ffmem_free(c);
}

static void conf_init(struct nml_http_client_conf *conf)
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

int nml_http_client_conf(nml_http_client *c, struct nml_http_client_conf *conf)
{
	if (!c) {
		conf_init(conf);
		return 0;
	}

	c->conf = conf;
	c->log_level = conf->log_level;
	c->log_obj = conf->log_obj;
	c->log = conf->log;
	ffmem_copy(c->id, conf->id, sizeof(c->id));

	c->wake = (void*)nml_http_client_run;

	if (!(c->kev = conf->core.kev_new(conf->boss)))
		return -1;
	c->kev->rhandler = (void*)nml_http_client_run;
	c->kev->whandler = (void*)nml_http_client_run;
	c->kev->kcall.handler = (void*)nml_http_client_run;
	c->kev->kcall.param = c;

	conveyor_init(&c->conveyor, (const nml_component**)conf->chain);

#ifdef NML_ENABLE_LOG_EXTRA
	if (c->log_level >= NML_LOG_DEBUG) {
		c->conveyor.log = conf->log;
		c->conveyor.log_obj = conf->log_obj;
		c->conveyor.log_ctx = "http-cl";
		c->conveyor.log_id = c->id;
	}
#endif

	return 0;
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

/** Call the current component */
static int conveyor_component_call(nml_http_client *c, uint i)
{
	struct nml_conveyor *v = &c->conveyor;
	const nml_http_cl_component *f = (nml_http_cl_component*)v->filters[i];
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

static void ocl_signal_parent(nml_http_client *c)
{
	c->conf->wake(c->conf->wake_param);
}

void nml_http_client_run(nml_http_client *c)
{
	struct nml_conveyor *v = &c->conveyor;

	int i = v->cur, r;
	for (;;) {

		if (v->rt[i].done) {
			r = (!c->chain_going_back) ? NMLF_FWD : NMLF_BACK;
			if (r == NMLF_FWD)
				c->output = c->input;
		} else {
			r = conveyor_component_call(c, i);
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
			i = 0;
			break;

		default:
			FF_ASSERT(0);
			goto end;
		}

		v->cur = i;
	}

end:
	ocl_signal_parent(c);
}

const struct nml_http_client_if nml_http_client_interface = {
	nml_http_client_create,
	nml_http_client_free,
	nml_http_client_conf,
	nml_http_client_run,
};
