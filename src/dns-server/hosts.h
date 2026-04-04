/** netmill: dns-server: hosts
2023, Simon Zolin */

#include <dns-server/conn.h>
#include <ffsys/perf.h>
#include <ffsys/file.h>

#define DSC_SYSERR(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_SYSERR, "hosts", NULL, __VA_ARGS__)

#define DSC_SYSWARN(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_SYSWARN, "hosts", NULL, __VA_ARGS__)

#define DSC_WARN(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_WARN, "hosts", NULL, __VA_ARGS__)

#define DSC_INFO(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_INFO, "hosts", NULL, __VA_ARGS__)

#define DSC_VERBOSE(conf, ...) \
	conf->log(conf->log_obj, NML_LOG_VERBOSE, "hosts", NULL, __VA_ARGS__)

#define DSC_DEBUG(conf, ...) \
do { \
	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG)) \
		conf->log(conf->log_obj, NML_LOG_DEBUG, "hosts", NULL, __VA_ARGS__); \
} while (0)

struct source {
	ffstr	name; // NULL-terminated
	fftime	mtime;
	ffvec	data; // char[]
	ffvec	entries; // struct hosts_entry[]
	ffvec	entries_ip; // struct hosts_entry_ip[]
};

#include <hosts-base.h>

/** Read hosts from file */
static int ds_source_read(struct nml_dns_server_conf *conf, struct source *src)
{
	DSC_DEBUG(conf, "reading %s", src->name.ptr);
	ffvec data = {};
	if (fffile_readwhole(src->name.ptr, &data, -1)) {
		DSC_SYSERR(conf, "file read: %S", &src->name);
		goto err;
	}

	fftime tstart = fftime_monotonic();

	uint fmt = hosts_format(*(ffstr*)&data);

	ffvec ents = {};
	uint n;
	if (fmt & T_IPV4) {
		n = hosts_read_ip(&conf->hosts.hosts, &ents, *(ffstr*)&data, conf->log, conf->log_obj);
		ffvec_free(&src->entries_ip);
		src->entries_ip = ents;
	} else {
		n = hosts_read(&conf->hosts.hosts, &ents, *(ffstr*)&data, conf->log, conf->log_obj);
		ffvec_free(&src->entries);
		src->entries = ents;
	}

	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG)) {
		fftime tstop = fftime_monotonic();
		fftime_sub(&tstop, &tstart);
		DSC_INFO(conf, "added %u from %s (%ums)"
			, n, src->name.ptr, (uint)fftime_to_msec(&tstop));

		_ffmap_stats(&conf->hosts.hosts.index, 0);
	}

	fffileinfo fi;
	if (!fffile_info_path(src->name.ptr, &fi))
		src->mtime = fffileinfo_mtime(&fi);

	ffvec_free(&src->data);
	src->data = data;
	return 0;

err:
	ffvec_free(&data);
	return -1;
}

/**
Return rule type;
  <0 if no match */
static int ds_hosts_find(struct nml_dns_server_conf *conf, const ffdns_question *q, ffip6 *ip)
{
	if (q->name.len <= 1)
		return 0;

	ffstr name;
	ffstr_set2(&name, &q->name);
	ffstr_rskipchar1(&name, '.');

	uint subdomain_match;
	const struct hosts_entry *ent = hosts_find(&conf->hosts.hosts, name, &subdomain_match);
	if (!ent) {
		conf->stat.hosts.misses++;
		return -1;
	}

	int t = ent->type & (T_BLOCK | T_PASS);
	if (!subdomain_match && ent->type == T_IPV4 && q->type == FFDNS_A) {
		const struct hosts_entry_ip *ent_ip = (struct hosts_entry_ip*)ent;
		ffmem_copy(ip, ent_ip->ip, 4);
		t = T_IPV4;

	} else if (!subdomain_match && ent->type == T_IPV6 && q->type == FFDNS_AAAA) {
		const struct hosts_entry_ip *ent_ip = (struct hosts_entry_ip*)ent;
		ffmem_copy(ip, ent_ip->ip, 16);
		t = T_IPV6;

	} else if (!subdomain_match && ent->type != T_PASS) {
		t = T_BLOCK;
	}

	if (t == 0) {
		conf->stat.hosts.misses++;
		return -1;
	}

	conf->stat.hosts.hits++;
	DSC_DEBUG(conf, "%S matches rule %S/%u"
		, &name, &q->name, ent->type);

	return t;
}

int nml_dns_hosts_find(struct nml_dns_server_conf *conf, ffstr name, ffip6 *ip)
{
	ffdns_question q = {};
	ffvec_set2(&q.name, &name);
	q.type = FFDNS_A;
	int t = ds_hosts_find(conf, &q, ip);
	if (t == T_IPV4) {
		ffip6_v4mapped_set(ip, (void*)ip);
		return 4;
	// } else if (t == T_IPV6) {
	// 	return 6;
	}
	return -1;
}

/** Add existing hosts to a map */
static int ds_source_addhosts(struct nml_dns_server_conf *conf, struct source *src)
{
	if (ffmap_grow(&conf->hosts.hosts.index, src->entries.len))
		return -1;

	struct hosts_entry *ent;
	FFSLICE_WALK(&src->entries, ent) {
		ffstr host = entry_host(ent);
		uint hash = ffmap_hash(host.ptr, host.len);
		void *val = ffmap_find_hash(&conf->hosts.hosts.index, hash, host.ptr, host.len, NULL);
		if (val) {
			DSC_VERBOSE(conf, "overwriting the existing entry for %S", &host);
			ffmap_rm_hash(&conf->hosts.hosts.index, hash, val);
		}

		ffmap_add_hash(&conf->hosts.hosts.index, hash, ent);
	}

	struct hosts_entry_ip *ent_ip;
	FFSLICE_WALK(&src->entries_ip, ent_ip) {
		ffstr host = entry_host((struct hosts_entry*)ent_ip);
		uint hash = ffmap_hash(host.ptr, host.len);
		void *val = ffmap_find_hash(&conf->hosts.hosts.index, hash, host.ptr, host.len, NULL);
		if (val) {
			DSC_VERBOSE(conf, "overwriting the existing entry for %S", &host);
			ffmap_rm_hash(&conf->hosts.hosts.index, hash, val);
		}

		ffmap_add_hash(&conf->hosts.hosts.index, hash, ent_ip);
	}

	DSC_INFO(conf, "added %L from %s"
		, src->entries.len, src->name.ptr);
	return 0;
}

static int ds_source_read_all(struct nml_dns_server_conf *conf)
{
	hosts_init(&conf->hosts.hosts);

	struct source *src;
	FFSLICE_WALK(&conf->hosts.sources, src) {
		if (src->mtime.sec != 0) {
			ds_source_addhosts(conf, src);
			continue;
		}
		ds_source_read(conf, src);
	}

	size_t total = 0;
	FFSLICE_WALK(&conf->hosts.sources, src) {
		total += src->data.len + src->entries.len * sizeof(struct hosts_entry);
	}
	DSC_INFO(conf, "total:%LB/%L"
		, total + conf->hosts.hosts.index.cap * sizeof(struct _ffmap_item), conf->hosts.hosts.index.len);
	return 0;
}

void nml_dns_hosts_refresh(struct nml_dns_server_conf *conf)
{
	DSC_DEBUG(conf, "refreshing...");

	uint n = 0;
	struct source *src;
	FFSLICE_WALK(&conf->hosts.sources, src) {

		fffileinfo fi;
		if (fffile_info_path(src->name.ptr, &fi)) {
			DSC_SYSWARN(conf, "file DSC_INFO: %s", src->name.ptr);
			continue;
		}

		fftime mtime = fffileinfo_mtime(&fi);
		if (!fftime_cmp(&mtime, &src->mtime))
			continue; // file isn't changed

		fftime_null(&src->mtime);
		DSC_DEBUG(conf, "file %s has been modified, reloading...", src->name.ptr);
		n++;
	}

	if (n == 0)
		return; // nothing to update

	hosts_destroy(&conf->hosts.hosts);
	ds_source_read_all(conf);
}

static void ds_hosts_timer(void *param) { nml_dns_hosts_refresh(param); }

#ifdef FF_LINUX
static void ds_hosts_on_change(void *param)
{
	struct nml_dns_server_conf *conf = param;
	int refresh = 0;
	for (;;) {
		int r = fffilemon_read_async(conf->hosts.fm, conf->hosts.fm_buf, sizeof(conf->hosts.fm_buf), NULL);
		if (r < 0) {
			if (fferr_last() != FFFILEMON_EINPROGRESS)
				DSC_SYSERR(conf, "fffilemon_read_async");
			break;
		}
		DSC_DEBUG(conf, "fffilemon_read_async: %u", r);

		ffstr s = FFSTR_INITN(conf->hosts.fm_buf, r);
		for (;;) {
			ffstr name;
			uint ev;
			int wd = fffilemon_next(conf->hosts.fm, &s, &name, NULL, &ev);
			if (wd < 0)
				break;
			refresh = 1;
			DSC_DEBUG(conf, "file changed: %d %xu", wd, ev);
		}
	}

	if (refresh)
		nml_dns_hosts_refresh(conf);
}
#endif

static void ds_hosts_monitor_change(struct nml_dns_server_conf *conf)
{
	if (!conf->hosts.monitor_change) return;

#ifdef FF_LINUX
	if (FFFILEMON_NULL == (conf->hosts.fm = fffilemon_open(IN_NONBLOCK))) {
		DSC_SYSWARN(conf, "fffilemon_open");
		return;
	}

	conf->hosts.fm_kev.rhandler = ds_hosts_on_change;
	conf->hosts.fm_kev.rtask.active = 1;
	if (conf->core.kq_attach(conf->boss, conf->hosts.fm, &conf->hosts.fm_kev, conf))
		return;

	struct source *src;
	FFSLICE_WALK(&conf->hosts.sources, src) {
		// Note: this fails for non-existing files
		if (-1 == fffilemon_add(conf->hosts.fm, src->name.ptr, FFFILEMON_EV_CHANGE))
			DSC_SYSWARN(conf, "fffilemon_add: %s", src->name.ptr);
	}
#endif
}

void nml_dns_hosts_init(struct nml_dns_server_conf *conf)
{
	const char **fn;
	FFSLICE_WALK(&conf->hosts.filenames, fn) {
		struct source *src = ffvec_zpushT(&conf->hosts.sources, struct source);
		src->name = FFSTR_Z(*fn);
	}
	ds_source_read_all(conf);
	conf->core.timer(conf->boss, &conf->hosts.refresh_timer, conf->hosts.file_refresh_period_sec * 1000, ds_hosts_timer, conf);
	ds_hosts_monitor_change(conf);
}

void nml_dns_hosts_uninit(struct nml_dns_server_conf *conf)
{
	hosts_destroy(&conf->hosts.hosts);

	struct source *src;
	FFSLICE_WALK(&conf->hosts.sources, src) {
		ffvec_free(&src->data);
		ffvec_free(&src->entries);
		ffvec_free(&src->entries_ip);
	}
	ffvec_free(&conf->hosts.sources);
}

static int ds_hosts_open(nml_dns_sv_conn *c)
{
	if (c->status)
		return NMLR_SKIP;
	return NMLR_OPEN;
}

static void ds_hosts_close(nml_dns_sv_conn *c)
{
}

/** Prepare response to a client according to configuration */
static int ds_block_resp(nml_dns_sv_conn *c)
{
	int rcode = FFDNS_NOERROR;

	switch (c->conf->hosts.block_mode) {

	case NML_DNS_BLOCK_EMPTY:
		break;

	case NML_DNS_BLOCK_NXDOMAIN:
		rcode = FFDNS_NXDOMAIN;  break;

	case NML_DNS_BLOCK_REFUSED:
		rcode = FFDNS_REFUSED;  break;

	case NML_DNS_BLOCK_NULL_IP:
		if (c->req.q.type == FFDNS_A) {
			*(uint*)&c->ip = 0; // 0.0.0.0
			ffstr_set(&c->answer.data, &c->ip, 4);
		} else if (c->req.q.type == FFDNS_AAAA) {
			// ::
			ffmem_copy(&c->ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
			ffstr_set(&c->answer.data, &c->ip, 16);
		}
		break;

	case NML_DNS_BLOCK_LOCAL_IP:
		if (c->req.q.type == FFDNS_A) {
			ffmem_copy(&c->ip, "\x7f\x00\x00\x01", 4); // 127.0.0.1
			ffstr_set(&c->answer.data, &c->ip, 4);
		} else if (c->req.q.type == FFDNS_AAAA) {
			// ::1
			ffmem_copy(&c->ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16);
			ffstr_set(&c->answer.data, &c->ip, 16);
		}
		break;

	case NML_DNS_BLOCK_DROP:
		DS_VERBOSE(c, "client: response: %u %S (%u) %LB (%s)"
			, c->req.q.type, &c->req.q.name, c->req.h.id, c->reqbuf.len, "hosts-block");
		return NMLR_FIN;
	}

	c->rcode = rcode;
	c->answer.ttl = c->conf->hosts.block_ttl;
	c->status = "hosts-block";
	return NMLR_DONE;
}

static int ds_hosts_process(nml_dns_sv_conn *c)
{
	if (c->req.q.type == FFDNS_AAAA && c->conf->hosts.block_aaaa) {
		c->status = "aaaa-block";
		return NMLR_DONE;
	}

	int t = ds_hosts_find(c->conf, &c->req.q, &c->ip);
	if (t < 0) {
		c->rcode = FFDNS_NXDOMAIN;
		return NMLR_DONE;

	} else if (t == T_PASS) {
		return NMLR_DONE;

	} else if (t == T_BLOCK) {
		int r = ds_block_resp(c);
		if (r != NMLR_DONE)
			return r;

	} else {
		c->answer.ttl = c->conf->hosts.rewrite_ttl;
		if (c->req.q.type == FFDNS_A)
			ffstr_set(&c->answer.data, &c->ip, 4);
		else
			ffstr_set(&c->answer.data, &c->ip, 16);
		c->status = "hosts-rewrite";
	}

	c->answer.name = c->req.q.name;
	c->answer.type = c->req.q.type;
	c->answer.clas = FFDNS_IN;
	return NMLR_DONE;
}

const nml_dns_component nml_dns_hosts = {
	ds_hosts_open, ds_hosts_close, ds_hosts_process,
	"hosts"
};

#undef DSC_SYSERR
#undef DSC_SYSWARN
#undef DSC_WARN
#undef DSC_INFO
#undef DSC_VERBOSE
#undef DSC_DEBUG
