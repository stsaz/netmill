/** network: Ethernet
2017, Simon Zolin */

/*
eth_copy eth_swap eth_iszero
eth_str eth_parse
eth_hdr_fill
eth_hdr_str
*/

#pragma once
#include <ffbase/string.h>

#define ETH_STRLEN  17

#define eth_copy(dst, src)  memcpy(dst, src, 6)

static inline void eth_swap(void *a, void *b)
{
	uint64 tmp = *(uint64*)a;
	memcpy(a, b, 6);
	memcpy(b, &tmp, 6);
}

/** Return TRUE if address is "00:00:00:00:00:00". */
static inline int eth_iszero(const void *eth)
{
	return (*(uint*)eth == 0
		&& *(uint*)((char*)eth + 2) == 0);
}

/** Convert Ethernet address to string.
Return number of bytes written;
	0 if not enough space. */
static inline uint eth_str(const void *eth, char *buf, size_t cap)
{
	if (cap < ETH_STRLEN) return 0;

	const u_char *u = eth;
	for (uint i = 0;  ;  i++) {
		buf[0] = ffhex[u[i] >> 4];
		buf[1] = ffhex[u[i] & 0x0f];
		if (i == 5)
			break;
		buf[2] = ':';
		buf += 3;
	}

	return ETH_STRLEN;
}

/** Parse Ethernet address from string.
Return 0 if the whole input is parsed;
	>0 number of processed bytes;
	<0 on error. */
static inline int eth_parse(void *eth, const char *s, size_t len)
{
	if (len < ETH_STRLEN) return -1;

	u_char *dst = eth;
	for (uint i = 0;;  i += 3) {
		int hi = ffchar_tohex(s[i]);
		int lo = ffchar_tohex(s[i + 1]);
		*dst++ = (hi << 4) | lo;

		if (hi < 0 || lo < 0)
			return -1;
		if (i + 2 == ETH_STRLEN)
			break;
		if (s[i + 2] != ':')
			return -1;
	}

	return (len == ETH_STRLEN) ? 0 : ETH_STRLEN;
}

struct eth_hdr {
	u_char dst[6], src[6];
	u_char type[2]; // enum ETH_T
};

enum ETH_T {
	ETH_IP4 = 0x0800,
	ETH_ARP = 0x0806,
	ETH_VLAN = 0x8100,
	ETH_IP6 = 0x86dd,
	ETH_MPLS = 0x8847,
};

static inline uint eth_hdr_fill(struct eth_hdr *h, const void *src, const void *dst, uint type)
{
	eth_copy(h->dst, dst);
	eth_copy(h->src, src);
	*(ushort*)h->type = ffint_be_cpu16(type);
	return sizeof(struct eth_hdr);
}

static inline int eth_hdr_str(const struct eth_hdr *h, char *buf, size_t cap)
{
	char src[ETH_STRLEN], dst[ETH_STRLEN];
	eth_str(h->src, src, sizeof(src));
	eth_str(h->dst, dst, sizeof(dst));
	return ffs_format(buf, cap, "%*s -> %*s  type:%04xu"
		, (size_t)ETH_STRLEN, src
		, (size_t)ETH_STRLEN, dst
		, ffint_be_cpu16_ptr(h->type));
}
