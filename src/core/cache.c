/** netmill: cache
2023, Simon Zolin */

#include <netmill.h>
#include <ffsys/perf.h>

struct nml_cache_ctx {
	struct nml_cache_conf conf;
	fflock	lock;
	ffmap	map;
	fflist	age;
};

#define CX_DEBUG(cx, ...) \
do { \
	if (cx->conf.log_level >= NML_LOG_DEBUG) \
		cx->conf.log(cx->conf.log_obj, NML_LOG_DEBUG, "cache", NULL, __VA_ARGS__); \
} while (0)

struct cache_entry {
	ffchain_item age_node;
	uint	expire_sec;
	ffstr	name;
	size_t	data_cap;
	size_t	data_len;
	char	data[0];
};

static void cache_unlink(nml_cache_ctx *cx, struct cache_entry *ce)
{
	ffmap_rm(&cx->map, ce->name.ptr, ce->name.len, NULL);
	fflist_rm(&cx->age, &ce->age_node);
}

static void cache_del(nml_cache_ctx *cx, struct cache_entry *ce)
{
	ffstr data = FFSTR_INITN(ce->data, ce->data_len);
	cx->conf.destroy(cx->conf.opaque, ce->name, data);
	CX_DEBUG(cx, "delete: %*xb", ce->name.len, ce->name.ptr);
	ffmem_free(ce);
}

static void cache_unlink_del(nml_cache_ctx *cx, struct cache_entry *ce)
{
	cache_unlink(cx, ce);
	cache_del(cx, ce);
}

static int cache_entry_keyeq(void *opaque, const void *key, size_t keylen, void *val)
{
	const struct cache_entry *ce = val;
	return ffstr_eq(&ce->name, key, keylen);
}

nml_cache_ctx* nml_cache_create()
{
	nml_cache_ctx *cx = ffmem_new(nml_cache_ctx);
	if (!cx) return NULL;

	ffmap_init(&cx->map, cache_entry_keyeq);
	fflist_init(&cx->age);
	return cx;
}

void nml_cache_destroy(nml_cache_ctx *cx)
{
	if (!cx) return;

	struct _ffmap_item *it;
	FFMAP_WALK(&cx->map, it) {
		if (!_ffmap_item_occupied(it))
			continue;
		struct cache_entry *ce = it->val;
		cache_unlink_del(cx, ce);
	}

	ffmap_free(&cx->map);
	ffmem_free(cx);
}

static void cache_log_dummy(void *log_obj, uint level, const char *ctx, const char *id, const char *format, ...)
{}

static fftime cache_timestamp(void *opaque)
{
	return fftime_monotonic();
}

static void cache_conf_init(struct nml_cache_conf *conf)
{
	ffmem_zero_obj(conf);
	conf->log_level = NML_LOG_INFO;
	conf->log = cache_log_dummy;

	conf->max_items = 1000000;
	conf->ttl_sec = 10*60;

	conf->timestamp = cache_timestamp;
}

int nml_cache_conf(nml_cache_ctx *cx, struct nml_cache_conf *conf)
{
	if (!cx) {
		cache_conf_init(conf);
		return 0;
	}

	cx->conf = *conf;
	return 0;
}

ffstr nml_cache_reserve(nml_cache_ctx *cx, size_t data_len)
{
	struct cache_entry *ce = ffmem_alloc(sizeof(struct cache_entry) + data_len);
	if (!ce)
		return FFSTR_Z("");
	ffmem_zero_obj(ce);
	ce->data_cap = data_len;
	ffstr data = FFSTR_INITN(ce->data, data_len);
	return data;
}

void nml_cache_free(nml_cache_ctx *cx, ffstr data)
{
	struct cache_entry *ce = FF_CONTAINER(struct cache_entry, data, data.ptr);
	cache_del(cx, ce);
}

int nml_cache_add(nml_cache_ctx *cx, ffstr name, ffstr data)
{
	int rc = -1;
	struct cache_entry *ce = FF_CONTAINER(struct cache_entry, data, data.ptr);
	NML_ASSERT(data.ptr == ce->data);
	NML_ASSERT(data.len <= ce->data_cap);
	ce->name = name;
	ce->data_len = data.len;
	fftime now = cx->conf.timestamp(cx->conf.opaque);
	ce->expire_sec = now.sec + cx->conf.ttl_sec;

	fflock_lock(&cx->lock);
	if (cx->map.len >= cx->conf.max_items) {
		void *it = fflist_first(&cx->age);
		if (it != fflist_sentl(&cx->age)) {
			struct cache_entry *ce_del = FF_CONTAINER(struct cache_entry, age_node, it);
			cache_unlink_del(cx, ce_del);
		}
	}

	if (ffmap_add(&cx->map, name.ptr, name.len, ce))
		goto end;

	fflist_add(&cx->age, &ce->age_node);
	CX_DEBUG(cx, "add: %*xb", name.len, name.ptr);
	rc = 0;

end:
	fflock_unlock(&cx->lock);
	return rc;
}

ffstr nml_cache_fetch(nml_cache_ctx *cx, ffstr name)
{
	int rc = -1;

	fflock_lock(&cx->lock);
	struct cache_entry *ce = ffmap_find(&cx->map, name.ptr, name.len, NULL);
	if (!ce)
		goto end;

	cache_unlink(cx, ce);

	fftime now = cx->conf.timestamp(cx->conf.opaque);
	if (now.sec >= ce->expire_sec) {
		cache_del(cx, ce);
		goto end;
	}

	CX_DEBUG(cx, "fetch: %*xb", name.len, name.ptr);
	rc = 0;

end:
	fflock_unlock(&cx->lock);
	if (rc)
		return FFSTR_Z("");
	ffstr data = FFSTR_INITN(ce->data, ce->data_len);
	return data;
}

const struct nml_cache_if nml_cache_interface = {
	nml_cache_create,
	nml_cache_destroy,
	nml_cache_conf,
	nml_cache_reserve,
	nml_cache_free,
	nml_cache_add,
	nml_cache_fetch,
};
