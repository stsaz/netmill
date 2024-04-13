/** netmill: dns-server: hosts
2023, Simon Zolin */

#include <dns-server/conn.h>
#include <ffbase/map.h>
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

enum TYPE {
	T_BLOCK = 1, // block domain and its subdomains
	T_PASS = 2, // pass domain and its subdomains
	T_IPV4 = 4, // assign IPv4 address to domain
	T_IPV6 = 8, // assign IPv6 address to domain
};

#pragma pack(push)
#pragma pack(4)
struct entry {
	const char *host_ptr; // -> source.data
	ushort host_len;
	ushort type; // enum TYPE
};

struct entry_ip {
	const char *host_ptr;
	ushort host_len;
	ushort type; // enum TYPE
	u_char ip[16]; // for T_IPV4 and T_IPV6
};
#pragma pack(pop)

struct source {
	ffstr	name; // NULL-terminated
	fftime	mtime;
	ffvec	data; // char[]
	ffvec	entries; // struct entry[]
	ffvec	entries_ip; // struct entry_ip[]
};

static ffstr entry_host(const struct entry *ent)
{
	ffstr host = FFSTR_INITN(ent->host_ptr, ent->host_len);
	return host;
}

static int map_keyeq(void *opaque, const void *key, size_t keylen, void *val)
{
	(void)opaque;
	struct entry *ent = (struct entry*)val;
	ffstr host = entry_host(ent);
	return ffstr_eq(&host, key, keylen);
}

/** Count the number of hosts */
static uint source_count_hosts(const ffstr *data, uint *_n_ip)
{
	uint n = 0, n_ip = 0;
	ffstr d = *data, ln, host, skip = FFSTR_INITZ(" \t\r");

	while (d.len) {
		ffstr_splitby(&d, '\n', &ln, &d);
		int type = -1;

		while (ln.len) {

			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#')
				break; // skip comment
			if (type < 0 && ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &host, &ln);

			if (type < 0) {
				// detect line format
				ffip6 ip;
				if (!ffip4_parse((ffip4*)&ip, host.ptr, host.len)) {
					type = T_IPV4;
					continue;
				} else if (!ffip6_parse(&ip, host.ptr, host.len)) {
					type = T_IPV6;
					continue;
				}
				type = T_BLOCK;
			}

			n++;
			if (type == T_IPV4 || type == T_IPV6)
				n_ip++;
		}
	}

	*_n_ip = n_ip;
	return n;
}

/** Add hosts them to a map.
Syntax:
  # comment
  ! comment
  BASE_HOST...
  +BASE_HOST...
  ||BASE_HOST^
  IP EXACT_HOST...
*/
static int ds_source_parse(struct nml_dns_server_conf *conf, struct source *src, ffstr data)
{
	int rc = -1;
	uint n = 0, n_ip;
	ffvec entries = {};
	ffvec entries_ip = {};
	fftime tstart = fftime_monotonic();

	n = source_count_hosts(&data, &n_ip);
	DSC_DEBUG(conf, "source_count_hosts:%u", n);
	if (ffmap_grow(&conf->hosts.index, n))
		goto end;
	ffvec_allocT(&entries, n - n_ip, struct entry);
	ffvec_allocT(&entries_ip, n_ip, struct entry_ip);
	n = 0;

	ffstr d = data, ln, host, ipstr, skip = FFSTR_INITZ(" \t\r");

	while (d.len) {
		ffstr_splitby(&d, '\n', &ln, &d);
		int type = -1;
		ffip6 ipaddr;

		while (ln.len) {

			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#')
				break; // skip comment
			if (type < 0 && ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &host, &ln);

			if (type < 0) {
				// detect line format

				if (host.len > 3
					&& host.ptr[0] == '|' && host.ptr[1] == '|' && host.ptr[host.len-1] == '^') {

					type = 0x0100 | T_BLOCK;
					host.ptr += 2;
					host.len -= 3;

				} else if (!ffip4_parse((ffip4*)&ipaddr, host.ptr, host.len)) {
					ipstr = host;
					type = T_IPV4;
					continue; // the first field is an IP

				} else if (!ffip6_parse(&ipaddr, host.ptr, host.len)) {
					ipstr = host;
					type = T_IPV6;
					continue; // the first field is an IP

				} else {
					type = T_BLOCK;
					if (host.ptr[0] == '+') {
						ffstr_shift(&host, 1);
						type = T_PASS;
					}
				}

			} else if (type == T_IPV4 || type == T_IPV6) {

			} else if (type == T_BLOCK) {
				if (host.ptr[0] == '+') {
					ffstr_shift(&host, 1);
					type = T_PASS;
				}

			} else if (type == T_PASS) {
				if (host.ptr[0] != '+') {
					type = T_BLOCK;
				}

			} else {
				DSC_WARN(conf, "unexpected value %S", &host);
				break;
			}

			if (0 > ffdns_isdomain(host.ptr, host.len)) {
				DSC_VERBOSE(conf, "invalid host name: %S", &host);
				continue;
			}

			ffstr_lower(&host);

			uint hash = ffmap_hash(host.ptr, host.len);
			struct entry *old, *ent;
			old = ffmap_find_hash(&conf->hosts.index, hash, host.ptr, host.len, NULL);
			if (old != NULL) {

				if (type != T_IPV4 && old->type == T_IPV4) {
					// "IP host" rule has higher priority than "host" rule
					DSC_VERBOSE(conf, "skipping (higher priority rule exists) %S: %u"
						, &host, old->type);
					continue;
				}

				ffmap_rm_hash(&conf->hosts.index, hash, old);

				DSC_VERBOSE(conf, "overwriting %S: %u"
					, &host, type & 0xff);
			}

			if (type == T_IPV4 || type == T_IPV6)
				ent = (struct entry*)_ffvec_push(&entries_ip, sizeof(struct entry_ip));
			else
				ent = _ffvec_push(&entries, sizeof(struct entry));

			ent->type = type & 0xff;
			ent->host_ptr = host.ptr;
			ent->host_len = host.len;

			if (type == T_IPV4) {
				struct entry_ip *ent_ip = (struct entry_ip*)ent;
				*(uint*)ent_ip->ip = *(uint*)&ipaddr;

			} else if (type == T_IPV6) {
				struct entry_ip *ent_ip = (struct entry_ip*)ent;
				ffmem_copy(ent_ip->ip, &ipaddr, 16);
			}

			ffmap_add_hash(&conf->hosts.index, hash, ent);
			n++;

			if (type & T_BLOCK) {
				DSC_DEBUG(conf, "block %S [%L]"
					, &host, conf->hosts.index.len);
			} else if (type == T_PASS) {
				DSC_DEBUG(conf, "pass %S [%L]"
					, &host, conf->hosts.index.len);
			} else {
				DSC_DEBUG(conf, "%S -> %S [%L]"
					, &host, &ipstr, conf->hosts.index.len);
			}
		}
	}

	fftime tstop = fftime_monotonic();
	fftime_sub(&tstop, &tstart);
	DSC_INFO(conf, "added %u from %s (%ums)"
		, n, src->name.ptr, (uint)fftime_to_msec(&tstop));
	if (ff_unlikely(conf->log_level >= NML_LOG_DEBUG))
		_ffmap_stats(&conf->hosts.index, 0);

	ffvec_free(&src->entries);
	ffvec_free(&src->entries_ip);
	src->entries = entries;
	src->entries_ip = entries_ip;

	fffileinfo fi;
	if (!fffile_info_path(src->name.ptr, &fi))
		src->mtime = fffileinfo_mtime(&fi);

	rc = 0;

end:
	if (rc != 0) {
		ffvec_free(&entries);
		ffvec_free(&entries_ip);
	}
	return 0;
}

/** Read hosts from file */
static int ds_source_read(struct nml_dns_server_conf *conf, struct source *src)
{
	DSC_DEBUG(conf, "reading %s", src->name.ptr);
	ffvec data = {};
	if (fffile_readwhole(src->name.ptr, &data, -1)) {
		DSC_SYSERR(conf, "file read: %S", &src->name);
		goto err;
	}

	if (ds_source_parse(conf, src, *(ffstr*)&data))
		goto err;

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

	int subdomain_match = 0;
	struct entry *ent;
	for (;;) {
		ent = ffmap_find(&conf->hosts.index, name.ptr, name.len, NULL);
		if (ent) {
			// "127.0.0.1 host.com" must not match "sub.host.com"
			if (!(subdomain_match
				&& (ent->type == T_IPV4 || ent->type == T_IPV6)))
				break;
		}
		// "a.b.c" -> "b.c"
		if (0 > ffstr_splitby(&name, '.', NULL, &name))
			break;
		subdomain_match = 1;
	}
	if (!ent) {
		conf->hosts.misses++;
		return -1;
	}

	int t = ent->type & (T_BLOCK | T_PASS);
	if (!subdomain_match && ent->type == T_IPV4 && q->type == FFDNS_A) {
		const struct entry_ip *ent_ip = (struct entry_ip*)ent;
		ffmem_copy(ip, ent_ip->ip, 4);
		t = T_IPV4;

	} else if (!subdomain_match && ent->type == T_IPV6 && q->type == FFDNS_AAAA) {
		const struct entry_ip *ent_ip = (struct entry_ip*)ent;
		ffmem_copy(ip, ent_ip->ip, 16);
		t = T_IPV6;
	}

	if (t == 0) {
		conf->hosts.misses++;
		return -1;
	}

	conf->hosts.hits++;
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
	if (ffmap_grow(&conf->hosts.index, src->entries.len))
		return -1;

	struct entry *ent;
	FFSLICE_WALK(&src->entries, ent) {
		ffstr host = entry_host(ent);
		uint hash = ffmap_hash(host.ptr, host.len);
		void *val = ffmap_find_hash(&conf->hosts.index, hash, host.ptr, host.len, NULL);
		if (val) {
			DSC_VERBOSE(conf, "overwriting the existing entry for %S", &host);
			ffmap_rm_hash(&conf->hosts.index, hash, val);
		}

		ffmap_add_hash(&conf->hosts.index, hash, ent);
	}

	struct entry_ip *ent_ip;
	FFSLICE_WALK(&src->entries_ip, ent_ip) {
		ffstr host = entry_host((struct entry*)ent_ip);
		uint hash = ffmap_hash(host.ptr, host.len);
		void *val = ffmap_find_hash(&conf->hosts.index, hash, host.ptr, host.len, NULL);
		if (val) {
			DSC_VERBOSE(conf, "overwriting the existing entry for %S", &host);
			ffmap_rm_hash(&conf->hosts.index, hash, val);
		}

		ffmap_add_hash(&conf->hosts.index, hash, ent_ip);
	}

	DSC_INFO(conf, "added %L from %s"
		, src->entries.len, src->name.ptr);
	return 0;
}

static int ds_source_read_all(struct nml_dns_server_conf *conf)
{
	ffmap_init(&conf->hosts.index, map_keyeq);

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
		total += src->data.len + src->entries.len * sizeof(struct entry);
	}
	DSC_INFO(conf, "total:%LB/%L"
		, total + conf->hosts.index.cap * sizeof(struct _ffmap_item), conf->hosts.index.len);
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

	ffmap_free(&conf->hosts.index);
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
	ffmap_free(&conf->hosts.index);

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
