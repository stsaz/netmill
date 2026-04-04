/** netmill: hosts
2023, Simon Zolin */

#include <ffbase/map.h>

enum TYPE {
	T_BLOCK = 1, // block domain and its subdomains
	T_PASS = 2, // pass domain and its subdomains
	T_IPV4 = 4, // assign IPv4 address to domain
	T_IPV6 = 8, // assign IPv6 address to domain
};

struct hosts_entry {
	u_char type; // enum TYPE
	u_char host_len;
	const char *host_ptr; // -> source.data
};

struct hosts_entry_ip {
	u_char type; // enum TYPE
	u_char host_len;
	const char *host_ptr;
	u_char ip[16]; // for T_IPV4 and T_IPV6
};

static ffstr entry_host(const struct hosts_entry *ent)
{
	ffstr host = FFSTR_INITN(ent->host_ptr, ent->host_len);
	return host;
}

static int map_keyeq(void *opaque, const void *key, size_t keylen, void *val)
{
	(void)opaque;
	struct hosts_entry *ent = (struct hosts_entry*)val;
	ffstr host = entry_host(ent);
	return ffstr_eq(&host, key, keylen);
}

void hosts_init(struct hosts *h)
{
	ffmap_init(&h->index, map_keyeq);
}

void hosts_destroy(struct hosts *h)
{
	ffmap_free(&h->index);
}

uint hosts_format(ffstr data)
{
	ffstr ln, word, skip = FFSTR_INITZ(" \t\r");
	ffip6 ipaddr;
	while (data.len) {
		ffstr_splitby(&data, '\n', &ln, &data);

		for (;;) {
			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#'
				|| ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &word, &ln);

			if (!ffip4_parse((ffip4*)&ipaddr, word.ptr, word.len)
				|| !ffip6_parse(&ipaddr, word.ptr, word.len))
				return T_IPV4 | T_IPV6;
			return T_BLOCK | T_PASS;
		}
	}
	return 0;
}

/** Count the number of hosts */
static uint hosts_count_ip(ffstr data)
{
	uint n = 0;
	ffstr ln, word, skip = FFSTR_INITZ(" \t\r");

	while (data.len) {
		ffstr_splitby(&data, '\n', &ln, &data);

		uint ip = 0;
		for (;;) {
			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &word, &ln);

			if (!ip) {
				ip = 1;
				continue;
			}

			n++;
		}
	}

	return n;
}

/** Count the number of hosts */
static uint hosts_count(ffstr data)
{
	uint n = 0;
	ffstr ln, host, skip = FFSTR_INITZ(" \t\r");

	while (data.len) {
		ffstr_splitby(&data, '\n', &ln, &data);

		for (;;) {
			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#'
				|| ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &host, &ln);
			n++;
		}
	}

	return n;
}


/**
Return 0: added;
 1: added, overwritten;
 -1: skip */
int hosts_add(struct hosts *h, struct hosts_entry *he, ffstr host, struct hosts_entry **old)
{
	int r = 0;
	uint hash = ffmap_hash(host.ptr, host.len);
	struct hosts_entry *ent;
	if ((ent = ffmap_find_hash(&h->index, hash, host.ptr, host.len, NULL))) {
		*old = ent;
		if ((he->type == T_BLOCK || he->type == T_PASS)
			&&
			(ent->type == T_IPV4 || ent->type == T_IPV6)) {
			// "IP host" rule has higher priority than "host" rule
			return -1;
		}

		ffmap_rm_hash(&h->index, hash, ent);
		r = 1;
	}

	ffmap_add_hash(&h->index, hash, he);
	return r;
}

/** Add hosts to a hash table.
Syntax:

# comment
IP EXACT_HOST...

Return N of hosts added. */
uint hosts_read_ip(struct hosts *h, ffvec *entries_ip, ffstr data, nml_log_func log, void *log_obj)
{
	uint n = hosts_count_ip(data);
	log(log_obj, NML_LOG_DEBUG, "hosts", NULL, "hosts_count_ip: %u", n);
	if (ffmap_grow(&h->index, n))
		return 0;
	ffvec_allocT(entries_ip, n, struct hosts_entry_ip);
	n = 0;

	ffstr ln, word, host, ipstr, skip = FFSTR_INITZ(" \t\r");

	while (data.len) {
		ffstr_splitby(&data, '\n', &ln, &data);
		int type = 0;
		ffip6 ipaddr = {};

		for (;;) {
			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#'
				|| ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &word, &ln);

			if (!type) {
				ipstr = word;
				if (!ffip4_parse((ffip4*)&ipaddr, word.ptr, word.len)) {
					type = T_IPV4;
					continue;

				} else if (!ffip6_parse(&ipaddr, word.ptr, word.len)) {
					type = T_IPV6;
					continue;
				}

				log(log_obj, NML_LOG_WARN, "hosts", NULL, "expected IP, got %S", &word);
				break; // skip this line
			}

			host = word;
			if (0 > ffdns_isdomain(host.ptr, host.len)) {
				log(log_obj, NML_LOG_WARN, "hosts", NULL, "invalid host name: %S", &host);
				break; // skip this line
			}

			ffstr_lower(&host);
			struct hosts_entry_ip *ent = _ffvec_push(entries_ip, sizeof(struct hosts_entry_ip));
			ent->type = type;
			ent->host_ptr = host.ptr;
			ent->host_len = host.len;
			ffmem_copy(ent->ip, &ipaddr, 16);

			struct hosts_entry *old;
			int r = hosts_add(h, (void*)ent, host, &old);
			if (r) {
				log(log_obj, NML_LOG_VERBOSE, "hosts", NULL, "overwriting %S: %u"
					, &host, type);
				old->type = 0;
			}

			n++;
			log(log_obj, NML_LOG_DEBUG, "hosts", NULL, "%S -> %S [%L]"
				, &host, &ipstr, h->index.len);
		}
	}

	return n;
}

/** Add hosts to a hash table.
Syntax:

# comment
! comment
BLOCK_BASE_HOST...
||BLOCK_BASE_HOST^
+ALLOW_BASE_HOST...

Return N of hosts added. */
uint hosts_read(struct hosts *h, ffvec *entries, ffstr data, nml_log_func log, void *log_obj)
{
	uint n = hosts_count(data);
	log(log_obj, NML_LOG_DEBUG, "hosts", NULL, "hosts_count: %u", n);
	if (ffmap_grow(&h->index, n))
		return 0;
	ffvec_allocT(entries, n, struct hosts_entry);
	n = 0;

	ffstr ln, host, skip = FFSTR_INITZ(" \t\r");
	int type;

	while (data.len) {
		ffstr_splitby(&data, '\n', &ln, &data);

		for (;;) {

			ffstr_skipany(&ln, &skip);
			if (!ln.len)
				break;
			if (ln.ptr[0] == '#'
				|| ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &host, &ln);
			if (!host.len)
				continue;

			type = T_BLOCK;
			if (host.len > 3
				&& host.ptr[0] == '|' && host.ptr[1] == '|'
				&& host.ptr[host.len-1] == '^') {

				host.ptr += 2;
				host.len -= 3;

			} else if (host.ptr[0] == '+') {
				ffstr_shift(&host, 1);
				type = T_PASS;
			}

			if (0 > ffdns_isdomain(host.ptr, host.len)) {
				log(log_obj, NML_LOG_WARN, "hosts", NULL, "invalid host name: %S", &host);
				break; // skip this line
			}

			ffstr_lower(&host);
			struct hosts_entry *ent = _ffvec_push(entries, sizeof(struct hosts_entry));
			ent->type = type;
			ent->host_ptr = host.ptr;
			ent->host_len = host.len;

			struct hosts_entry *old;
			int r = hosts_add(h, ent, host, &old);
			if (r < 0) {
				log(log_obj, NML_LOG_VERBOSE, "hosts", NULL, "skipping (higher priority rule exists) %S"
					, &host);
				entries->len--;
				continue;
			} else if (r > 0) {
				log(log_obj, NML_LOG_VERBOSE, "hosts", NULL, "overwriting %S: %u"
					, &host, type);
				old->type = 0;
			}

			n++;
			log(log_obj, NML_LOG_DEBUG, "hosts", NULL, "%s %S [%L]"
				, (type == T_BLOCK) ? "block" : "pass", &host, h->index.len);
		}
	}

	return n;
}

const struct hosts_entry* hosts_find(const struct hosts *h, ffstr name, uint *p_subdomain_match)
{
	uint subdomain_match = 0;
	struct hosts_entry *ent;
	for (;;) {
		ent = ffmap_find(&h->index, name.ptr, name.len, NULL);
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
	*p_subdomain_match = subdomain_match;
	return ent;
}
