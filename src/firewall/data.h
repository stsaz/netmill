/** netmill: firewall: user-kernel data
2024, Simon Zolin */

#include <linux/types.h>

struct nml_fw_rule_key {
	__u8 eth_proto[2];
	__u8 ip_proto; // ipv4.protocol or ipv6.nexthdr
	__u8 reserved;
	__u8 l4_src_port[2], l4_dst_port[2]; // (tcp|udp).(src|dst)
};

struct nml_fw_rule {
	__u8 dummy;
};

struct nml_fw_stats {
	__u64 matched;
	__u64 invalid;
};
