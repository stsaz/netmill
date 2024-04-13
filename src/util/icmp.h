/** network: ICMP */

/*
icmp_hdr_echo_request
*/

#pragma once

struct icmp_hdr {
	u_char type; // enum ICMP_TYPE
	u_char code;
	u_char crc[2];

	union {
	u_char hdr_data[4];
	struct {
		u_char id[2];
		u_char seq[2];
	} echo;
	};
};

enum ICMP_TYPE {
	ICMP_ECHO_REPLY = 0,
	ICMP_ECHO_REQUEST = 8,
};

static inline uint icmp_hdr_echo_request(struct icmp_hdr *h, uint id, uint seq, uint data_len)
{
	h->type = ICMP_ECHO_REQUEST;
	h->code = 0;
	*(ushort*)h->echo.id = ffint_be_cpu16(id);
	*(ushort*)h->echo.seq = ffint_be_cpu16(seq);
	*(ushort*)h->crc = 0;
	*(ushort*)h->crc = ip_sum(h, sizeof(*h) + data_len);
	return sizeof(struct icmp_hdr);
}
