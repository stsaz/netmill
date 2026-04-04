/** netmill: Static conveyor
2022, Simon Zolin */

#pragma once

#ifndef CONVEYOR_MAX_COMPS
	#define CONVEYOR_MAX_COMPS  32
#endif

typedef int (*process_f)(void *c);

struct nml_conveyor {
	process_f process[CONVEYOR_MAX_COMPS];
	const nml_component **comps;
	uint empty_data_counter;
	uint total, active, cur;
	uint opened; // bit[]
	uint done; // bit[]

#ifdef NML_ENABLE_LOG_EXTRA
	void (*log)(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...);
	void *log_obj;
	const char *log_ctx, *log_id;
#endif
};

#define conveyor_extralog(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef conveyor_extralog
	#define conveyor_extralog(v, ...) \
	do { \
		if (v->log != NULL) \
			v->log(v->log_obj, NML_LOG_EXTRA, v->log_ctx, v->log_id, __VA_ARGS__); \
	} while (0)
#endif

#define CONVEYOR_OPENED_TEST(v, i)  ffbit_test32(&v->opened, i)
#define CONVEYOR_DONE_TEST(v, i)  ffbit_test32(&v->done, i)

static inline int conveyor_open_once(struct nml_conveyor *v, uint i, void *object, const char ret_str[][11])
{
	(void)ret_str;
	if (!CONVEYOR_OPENED_TEST(v, i)) {
		const nml_component *f = v->comps[i];
		conveyor_extralog(v, "f#%u '%s': opening", i, f->name);
		if (f->open) {
			int r = f->open(object);
			conveyor_extralog(v, "  f#%u '%s': %s", i, f->name, ret_str[r]);
			if (r != NMLR_OPEN)
				return r;
		}
		v->process[i] = f->process;
		ffbit_set32(&v->opened, i);
	}
	return NMLR_OPEN;
}

static inline void conveyor_done(struct nml_conveyor *v, uint i)
{
	ffbit_set32(&v->done, i);
	v->active--;
	conveyor_extralog(v, "chain: %u", v->active);
	v->empty_data_counter = 0;
}

static inline int conveyor_fwd(struct nml_conveyor *v, uint i, size_t output_len)
{
	if (!CONVEYOR_DONE_TEST(v, i)) {
		if (!output_len) {
			if (ff_unlikely(v->empty_data_counter > v->active * 2))
				return -1;
			v->empty_data_counter++;
		} else {
			v->empty_data_counter = 0;
		}
	}
	return 0;
}

static inline void conveyor_init(struct nml_conveyor *v, const nml_component **comps)
{
	uint i;
	for (i = 0;  comps[i] != NULL;  i++) {}
	FF_ASSERT(i <= 32);
	v->total = i;
	v->active = i;
	v->comps = comps;
}

static inline void conveyor_reset(struct nml_conveyor *v)
{
	v->empty_data_counter = 0;
	v->active = v->total;
	v->cur = 0;
	v->opened = 0;
	v->done = 0;
}

/** Close all opened components */
static inline void conveyor_close(struct nml_conveyor *v, void *object)
{
	for (uint i = 0;  v->comps[i] != NULL;  i++) {
		if (CONVEYOR_OPENED_TEST(v, i)) {
			const nml_component *f = v->comps[i];
			conveyor_extralog(v, "f#%u '%s': closing", i, f->name);
			if (f->close != NULL)
				f->close(object);
		}
	}
}
