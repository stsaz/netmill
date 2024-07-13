/** netmill: dns-server: connection processor
2023, Simon Zolin */

#include <dns-server/conn.h>
#include <ffsys/perf.h>

static void ds_destroy(nml_dns_sv_conn *c)
{
	conveyor_close(&c->conveyor, c);
	ffstr_free(&c->reqbuf);
	ffmem_free(c);
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
static int ds_conveyor_component_call(nml_dns_sv_conn *c, uint i)
{
	struct nml_conveyor *v = &c->conveyor;
	const nml_dns_component *f = (nml_dns_component*)v->comps[i];
	int r;

	if (!CONVEYOR_OPENED_TEST(v, i)) {
		DS_EXTRALOG(c, "f#%u '%s': opening", i, f->name);
		r = f->open(c);
		(void)nmlf_r_str;
		DS_EXTRALOG(c, "  f#%u '%s': %s", i, f->name, nmlf_r_str[r]);
		if (r != NMLR_OPEN)
			return r;
		CONVEYOR_OPENED_SET(v, i);
	}

	DS_EXTRALOG(c, "f#%u '%s': input:%L", i, f->name, c->input.len);
	r = f->process(c);
	DS_EXTRALOG(c, "  f#%u '%s': %s  output:%L", i, f->name, nmlf_r_str[r], c->output.len);
	return r;
}

void ds_run(nml_dns_sv_conn *c)
{
	struct nml_conveyor *v = &c->conveyor;

	int i = v->cur, r;
	for (;;) {

		if (CONVEYOR_DONE_TEST(v, i)) {
			r = (!c->chain_going_back) ? NMLR_FWD : NMLR_BACK;
			if (r == NMLR_FWD)
				c->output = c->input;
		} else {
			r = ds_conveyor_component_call(c, i);
		}

		switch (r) {
		case NMLR_SKIP:
			c->output = c->input;
			// fallthrough
		case NMLR_DONE:
			CONVEYOR_DONE_SET(v, i);
			v->active--;
			v->empty_data_counter = 0;
			DS_EXTRALOG(c, "chain: %u", v->active);
			// fallthrough

		case NMLR_FWD:
			if (!CONVEYOR_DONE_TEST(v, i)) {
				if (!c->output.len) {
					if (v->empty_data_counter > v->active * 2) {
						DS_ERR(c, "detected chain processing loop");
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
				DS_ERR(c, "%s: the first filter asks for more input data", v->comps[i]->name);
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
	ds_destroy(c);
}

void ds_start(struct nml_dns_server_conf *conf, uint conn_id, ffsock sk, ffsockaddr *addr, ffstr request)
{
	nml_dns_sv_conn *c = ffmem_new(nml_dns_sv_conn);
	if (c == NULL) return;

	c->tstart = fftime_monotonic();
	c->sk = sk;
	c->conf = conf;
	c->peer = *addr;

	c->id[0] = '*';
	int r = ffs_fromint(conn_id, c->id+1, sizeof(c->id)-1, 0);
	c->id[r+1] = '\0';

	c->reqbuf = request;

	conveyor_init(&c->conveyor, (const nml_component**)c->conf->chain);

#ifdef NML_ENABLE_LOG_EXTRA
	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG)) {
		c->conveyor.log = conf->log;
		c->conveyor.log_obj = conf->log_obj;
		c->conveyor.log_ctx = "dns-sv";
		c->conveyor.log_id = c->id;
	}
#endif

	ds_run(c);
}
