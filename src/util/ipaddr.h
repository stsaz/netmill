/** network: IPv4/IPv6 address functions
2020, Simon Zolin
*/

/*
ffip4_cmp ffip6_cmp ffip6_isany
ffip4_mask
ffip6_v4mapped
ffip6_v4mapped_set
ffip6_tov4
CONVERT
	ffip4_parse ffip6_parse
	ffip4_parse_subnet ffip6_parse_subnet
	ffip_port_split
	ffip4_tostr ffip4_tostrz ffip6_tostr ffip6_tostrz ffip46_tostr
HEADERS
	ffip4_checksum
	ffip4_hdr_fill
	ffip4_hdr_str ffip6_hdr_str
	ip_sum
*/

#pragma once

#include <ffsys/string.h>

typedef struct { char a[4]; } ffip4;

#define FFIP4_STRLEN  15 // "000.000.000.000"

/** Compare two IPv4 addresses */
static inline int ffip4_cmp(const ffip4 *ip1, const ffip4 *ip2)
{
	return ffmem_cmp(ip1, ip2, sizeof(*ip1));
}

/** Convert subnet bits to mask.
e.g. 32 -> "255.255.255.255"
Return bytes written;
  <0 on error */
static inline int ffip4_mask(ffuint bits, char *mask, ffsize cap)
{
	union {
		ffuint m;
		ffbyte b[4];
	} u;
	if (bits > 32) {
		return -1;
	} else if (bits == 32) {
		u.m = 0xffffffff;
	} else {
		u.m = ~(0xffffffff >> bits);
		u.m = ffint_be_cpu32(u.m);
	}
	ffssize r = ffs_format(mask, cap, "%u.%u.%u.%u"
		, u.b[0], u.b[1], u.b[2], u.b[3]);
	if (r < 0)
		return -1;
	return r;
}

/** Parse IPv4 address.
Return 0 if the whole input is parsed;
  >0 number of processed bytes;
  <0 on error */
static inline int ffip4_parse(ffip4 *ip4, const char *s, ffsize len)
{
	ffuint nadr = 0, ndig = 0, b = 0, i;

	for (i = 0;  i != len;  i++) {
		int ch = s[i];

		if ((ch >= '0' && ch <= '9') && ndig != 3) {
			b = b * 10 + (ch) - '0';
			if (b > 255)
				return -1; // "256."
			ndig++;

		} else if (ndig == 0) {
			return -1; // "1.?"

		} else if (nadr == 3) {
			ip4->a[nadr] = b;
			return i;

		} else if (ch == '.') {
			ip4->a[nadr++] = b;
			b = 0;
			ndig = 0;

		} else {
			return -1;
		}
	}

	if (nadr == 3 && ndig != 0) {
		ip4->a[nadr] = b;
		return 0;
	}

	return -1;
}

#define ffip4_parsez(ip4, sz)  ffip4_parse(ip4, sz, ffsz_len(sz))

/** Parse IPv4+subnet pair, e.g. "1.2.3.0/24"
Return subnet mask bits;
  <0 on error */
static inline int ffip4_parse_subnet(ffip4 *ip4, const char *s, ffsize len)
{
	ffuint subnet = 0, r;
	r = ffip4_parse(ip4, s, len);
	if ((int)r <= 0)
		return -1;

	if (!(len >= r + 1 && s[r] == '/'))
		return -1;
	r++;

	if (len - r != ffs_toint(s + r, len - r, &subnet, FFS_INT32)
		|| subnet == 0 || subnet > 32)
		return -1;

	return subnet;
}

/** Convert IPv4 address to string.
Return the number of characters written;
  0 on error */
static inline ffuint ffip4_tostr(const ffip4 *ip4, char *dst, ffsize cap)
{
	char *p = dst, *end = dst + cap;
	if (cap < FFIP4_STRLEN)
		return 0;

	for (ffuint i = 0;  i != 4;  i++) {
		ffuint n = ffs_fromint((ffbyte)ip4->a[i], p, end - p, 0);
		if (n == 0)
			return 0;
		p += n;
		if (i != 3)
			*p++ = '.';
	}

	return p - dst;
}

static inline ffuint ffip4_tostrz(const ffip4 *ip4, char *dst, ffsize cap)
{
	ffuint r = ffip4_tostr(ip4, dst, cap);
	if (r == 0 || r == cap)
		return 0;
	dst[r] = '\0';
	return r;
}


typedef struct { char a[16]; } ffip6;

#define FFIP6_STRLEN  (FFS_LEN("abcd:") * 8 - 1)

/** Compare two IPv6 addresses */
static inline int ffip6_cmp(const ffip6 *ip1, const ffip6 *ip2)
{
	return memcmp(ip1, ip2, sizeof(*ip1));
}

static inline ffbool ffip6_isany(const ffip6 *ip)
{
	return *(ffuint64*)ip == 0 && *(((ffuint64*)ip)+1) == 0;
}

/** Return TRUE if it's an IPv4-mapped address */
static inline ffbool ffip6_v4mapped(const ffip6 *ip)
{
	const ffuint *i = (ffuint*)ip->a;
	return i[0] == 0 && i[1] == 0 && i[2] == ffint_be_cpu32(0x0000ffff);
}

/** Map IPv4 address to IPv6 */
static inline void ffip6_v4mapped_set(ffip6 *ip6, const ffip4 *ip4)
{
	ffuint *i = (ffuint*)ip6->a;
	i[3] = *(ffuint*)ip4;
	i[0] = i[1] = 0;
	i[2] = ffint_be_cpu32(0x0000ffff);
}

/** Return IPv4 address or NULL */
static inline const ffip4* ffip6_tov4(const ffip6 *ip)
{
	if (!ffip6_v4mapped(ip))
		return NULL;
	return (ffip4*)&ip->a[12];
}

/** Parse IPv6 address.
Note: v4-mapped address is not supported.
Return 0 if the whole input is parsed;
  >0: number of processed bytes;
  <0 on error */
static inline int ffip6_parse(ffip6 *a, const char *s, ffsize len)
{
	ffuint i, chunk = 0, ndigs = 0, idst = 0;
	char *dst = (char*)a;
	int hx, izero = -1;

	for (i = 0;  i != len;  i++) {
		int b = s[i];

		if (idst == 16)
			return -1; // too large input

		if (b == ':') {

			if (ndigs == 0) { // ":" or "...::"
				if (i == 0) { // ":"
					i++;
					if (i == len || s[i] != ':')
						return -1; // ":" or ":?"
				} else if (izero >= 0) {
					return -1; // second "::"
				}
				izero = idst;
				continue;
			}

			dst[idst++] = chunk >> 8;
			dst[idst++] = chunk & 0xff;
			ndigs = 0;
			chunk = 0;
			continue;
		}

		if (ndigs == 4)
			break; // ":12345"

		hx = ffchar_tohex(b);
		if (hx == -1)
			break; // invalid hex char

		chunk = (chunk << 4) | hx;
		ndigs++;
	}

	if (ndigs == 0 && (ffuint)izero != idst) {
		return -1; // ':' at the end, but not "...::"
	} else if (ndigs != 0) {
		dst[idst++] = chunk >> 8;
		dst[idst++] = chunk & 0xff;
	}

	if (izero >= 0) {
		// "123" -> "1.....23"
		ffuint nzero = 16 - idst;
		// move(&dst[izero + nzero], &dst[izero], idst - izero);
		// zero(&dst[izero], nzero);
		ffuint src = idst - 1;
		for (int k = 16 - 1;  k >= (int)(izero + nzero);  k--) {
			dst[k] = dst[src--];
		}
		for (ffuint k = izero;  k != izero + nzero;  k++) {
			dst[k] = 0x00;
		}
	} else if (idst != 16) {
		return -1; // too small input
	}

	return (i == len) ? 0 : i;
}

#define ffip6_parsez(ip6, sz)  ffip6_parse(ip6, sz, ffsz_len(sz))

/** Parse IPv6+subnet pair, e.g. "1:2:3::/64"
Return subnet mask bits;
  <0 on error */
static inline int ffip6_parse_subnet(ffip6 *ip6, const char *s, ffsize len)
{
	ffuint subnet = 0, r;
	r = ffip6_parse(ip6, s, len);
	if ((int)r <= 0)
		return -1;

	if (!(len >= r + 1 && s[r] == '/'))
		return -1;
	r++;

	if (len - r != ffs_toint(s + r, len - r, &subnet, FFS_INT32)
		|| subnet == 0 || subnet > 128)
		return -1;

	return subnet;
}

/** Convert IPv6 address to string.
Return the number of characters written.
Note: v4-mapped address is not supported */
static inline ffuint ffip6_tostr(const void *addr, char *dst, ffsize cap)
{
	const ffbyte *a = (ffbyte*)addr;
	char *p = dst;
	const char *end = dst + cap;
	int cut_from = -1, cut_len = 0;
	int zrbegin = 0, nzr = 0;

	if (cap < FFIP6_STRLEN)
		return 0;

	// get the maximum length of zeros to cut off
	for (int i = 0;  i < 16;  i += 2) {
		if (a[i] == '\0' && a[i + 1] == '\0') {
			if (nzr == 0)
				zrbegin = i;
			nzr += 2;

		} else if (nzr != 0) {
			if (nzr > cut_len) {
				cut_from = zrbegin;
				cut_len = nzr;
			}
			nzr = 0;
		}
	}

	if (nzr > cut_len) {
		// zeros at the end of address
		cut_from = zrbegin;
		cut_len = nzr;
	}

	for (int i = 0;  i < 16; ) {
		if (i == cut_from) {
			// cut off the sequence of zeros
			*p++ = ':';
			i = cut_from + cut_len;
			if (i == 16)
				*p++ = ':';
			continue;
		}

		if (i != 0)
			*p++ = ':';
		p += ffs_fromint(ffint_be_cpu16_ptr(&a[i]), p, end - p, FFS_INTHEX); // convert 16-bit number to string
		i += 2;
	}

	return p - dst;
}

static inline ffuint ffip6_tostrz(const ffip6 *ip6, char *dst, ffsize cap)
{
	ffuint r = ffip6_tostr(ip6, dst, cap);
	if (r == 0 || r == cap)
		return 0;
	dst[r] = '\0';
	return r;
}

/** Convert IPv4 or IPv6 address to string.
cap: FFIP6_STRLEN
Return N of bytes written;
  0: not enough capacity */
static inline ffuint ffip46_tostr(const ffip6 *ip, char *buf, ffsize cap)
{
	const ffip4 *ip4 = ffip6_tov4(ip);
	if (ip4 != NULL)
		return ffip4_tostr(ip4, buf, cap);
	return ffip6_tostr(ip, buf, cap);
}

/** Split "IP:port" string.
  e.g. "127.0.0.1", "::1", "80", "127.0.0.1:80", "[::1]:80"
Return:
 1: IP is set
 2: port is set
 3: both IP and port are set
 <0: error */
static inline int ffip_port_split(ffstr s, void *ip6, ffuint *port)
{
	char ip[16];
	int r = ffip4_parse((ffip4*)ip, s.ptr, s.len);
	if (r < 0) {
		// bad IPv4
		if (s.len == 0)
			return -1;

		ffuint brkt = (s.ptr[0] == '[');
		r = ffip6_parse((ffip6*)ip, s.ptr + brkt, s.len - brkt);

		if (brkt) {
			if (r <= 0 || s.ptr[r+1] != ']')
				return -2; // bad IPv6 in brackets
			r += 2;
		}

		if (r >= 0)
			ffmem_copy(ip6, ip, 16);
	} else {
		ffip6_v4mapped_set(ip6, (ffip4*)ip);
	}

	if (r == 0) {
		return 1; // "127.0.0.1" or "::1"

	} else if (r > 0) {
		if (s.ptr[r] != ':')
			return -3; // missing colon
		ffstr_shift(&s, r+1);
	}

	*port = 0;
	if (!ffstr_toint(&s, port, FFS_INT16))
		return -4; // bad port
	return (r > 0) | 2;
}

static inline void ffip4_swap(void *a, void *b)
{
	uint tmp = *(uint*)a;
	*(uint*)a = *(uint*)b;
	*(uint*)b = tmp;
}


struct ffip4_hdr {

#ifdef FF_BIG_ENDIAN
	u_char version :4 //=4
		, ihl :4; //>=5
	u_char dscp :6
		, ecn :2;
#else
	u_char ihl :4
		, version :4;
	u_char ecn :2
		, dscp :6;
#endif

	u_char total_len[2];
	u_char id[2];
	u_char frag[2]; // flags[3]:[res, dont_frag, more_frags]  frag_off[13]
	u_char ttl;
	u_char proto; // enum FFIP4_PROTO
	u_char crc[2];

	u_char src[4], dst[4];

	u_char opts[0];
};

enum FFIP4_PROTO {
	FFIP_ICMP = 1,
	FFIP_TCP = 6,
	FFIP_UDP = 17,
};

#define ffip4_hdr_frag_more(ip4) (!!((ip4)->frag[0] & 0x20))
#define ffip4_hdr_frag_dont(ip4) (!!((ip4)->frag[0] & 0x40))

/** Fragment offset.
The last one has `more_frags=0`. */
#define ffip4_hdr_frag_off(ip4)  ((ffint_be_cpu16_ptr((ip4)->frag) & 0x1fff) * 8)

#define ffip4_hdr_len(ip4)  ((ip4)->ihl * 4)

#define ffip4_hdr_datalen(ip4)  ffint_be_cpu16_ptr((ip4)->total_len) - ffip4_hdr_len(ip4)

/** Compute IPv4 header checksum. */
static inline uint ffip4_checksum(const void *ip4_hdr, uint ihl, uint with_checksum)
{
	const uint *n = ip4_hdr;

	uint64 sum = n[0];
	sum += n[1];
	sum += (with_checksum) ? n[2] : (n[2] & 0xffff);
	sum += n[3];
	sum += n[4];

	if (ff_unlikely(ihl > 5)) {
		for (uint i = 5;  i < ihl;  i++) {
			sum += n[i];
		}
	}

	// Add hi-word to low-word with Carry flag: (HI(sum) + LO(sum)) + CF
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	return ~sum & 0xffff;
}

static inline uint ffip4_hdr_fill(struct ffip4_hdr *h, uint data_len, uint id, uint ttl, uint proto
	, const void *src, const void *dst)
{
	*(ushort*)h = ffint_be_cpu16(0x4500);
	*(ushort*)h->total_len = ffint_be_cpu16(sizeof(struct ffip4_hdr) + data_len);
	*(ushort*)h->id = ffint_be_cpu16(id);
	*(ushort*)h->frag = 0;
	h->ttl = ttl;
	h->proto = proto;
	*(uint*)h->src = *(uint*)src;
	*(uint*)h->dst = *(uint*)dst;
	*(ushort*)h->crc = ffip4_checksum(h, 5, 0);
	return sizeof(struct ffip4_hdr);
}

static inline int ffip4_hdr_str(const struct ffip4_hdr *ip4, char *buf, size_t cap)
{
	char src[FFIP4_STRLEN], dst[FFIP4_STRLEN];
	uint ns = ffip4_tostr((ffip4*)ip4->src, src, sizeof(src));
	uint nd = ffip4_tostr((ffip4*)ip4->dst, dst, sizeof(dst));
	return ffs_format(buf, cap, "%*s -> %*s  id:%xu  len:%u  ttl:%u  proto:%xu"
		, ns, src
		, nd, dst
		, ffint_be_cpu16_ptr(ip4->id), ffint_be_cpu16_ptr(ip4->total_len), ip4->ttl, ip4->proto);
}


struct ffip6_hdr {
	u_char ver_tc_fl[4]; // ver[4] traf_class[8] flow_label[20]
	u_char payload_len[2];
	u_char next_hdr;
	u_char hop_limit;
	u_char src[16], dst[16];
};

#define ffip6_hdr_ver(ip6)  ((ip6)->ver_tc_fl[0] >> 4)

#define ffip6_hdr_datalen(ip6)  ffint_be_cpu16_ptr((ip6)->payload_len)

static inline int ffip6_hdr_str(const struct ffip6_hdr *ip6, char *buf, size_t cap)
{
	char src[FFIP6_STRLEN], dst[FFIP6_STRLEN];
	size_t ns = ffip6_tostr(ip6->src, src, FFIP6_STRLEN);
	size_t nd = ffip6_tostr(ip6->dst, dst, FFIP6_STRLEN);
	return ffs_format(buf, cap, "%*s -> %*s  len:%u  proto:%xu"
		, ns, src
		, nd, dst
		, ffint_be_cpu16_ptr(ip6->payload_len), ip6->next_hdr);
}


static ushort _ip_sum_carry(ushort sum, ushort add)
{
	ushort r = sum + add;
	return r + (r < add);
}

/** Reduce 48-bit number to 16-bit */
static uint _ip_sum_reduce(uint64 sum48)
{
	uint sum17 = (sum48 >> 32) + ((sum48 >> 16) & 0xffff) + (sum48 & 0xffff); // hi,mid,low -> CF,hi+mid+low
	return (sum17 >> 16) + (sum17 & 0xffff); // -> CF+(hi+mid+low)
}

/** Compute Internet checksum */
static inline ushort ip_sum(const void *buf, uint len)
{
	uint64 sum = 0;
	const uint *p = buf;
	while (len >= 4) {
		sum += *p++;
		len -= 4;
	}

	if (len >= 2) {
		sum += *(ushort*)p;
		p = (void*)((u_char*)p + 2);
		len -= 2;
	}

	if (len >= 1)
		sum += *(u_char*)p;

	return ~_ip_sum_reduce(sum);
}

static inline void ip_sum_replace(ushort *sum, ushort old, ushort _new)
{
	*sum = ~_ip_sum_carry(_ip_sum_carry(~(*sum), ~old), _new);
}
