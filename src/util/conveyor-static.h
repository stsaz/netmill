/** netmill: Static conveyor
2022, Simon Zolin */

#pragma once

struct nml_conveyor {
	const nml_component **comps;
	uint empty_data_counter;
	uint total, active, cur;
	struct {
		ffbyte opened :1;
		ffbyte done :1;
	} rt[16];

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

static inline void conveyor_init(struct nml_conveyor *v, const nml_component **comps)
{
	uint i;
	for (i = 0;  comps[i] != NULL;  i++) {}
	v->total = i;
	v->active = i;
	v->comps = comps;
}

static inline void conveyor_reset(struct nml_conveyor *v)
{
	v->empty_data_counter = 0;
	v->active = v->total;
	v->cur = 0;
	ffmem_zero_obj(&v->rt);
}

/** Close all opened components */
static inline void conveyor_close(struct nml_conveyor *v, void *object)
{
	for (uint i = 0;  v->comps[i] != NULL;  i++) {
		if (v->rt[i].opened) {
			const nml_component *f = v->comps[i];
			conveyor_extralog(v, "f#%u '%s': closing", i, f->name);
			if (f->close != NULL)
				f->close(object);
		}
	}
}
