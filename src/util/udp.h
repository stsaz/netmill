/** network: UDP */

#pragma once

struct udp_hdr {
	u_char sport[2], dport[2];
	u_char length[2];
	u_char crc[2];
};

static inline int udp_hdr_str(const struct udp_hdr *u, char *buf, size_t cap)
{
	return ffs_format(buf, cap, "%u -> %u  len:%u"
		, ffint_be_cpu16_ptr(u->sport), ffint_be_cpu16_ptr(u->dport)
		, ffint_be_cpu16_ptr(u->length));
}
