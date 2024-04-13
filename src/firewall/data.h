/** netmill: firewall: user-kernel data */

#include <linux/types.h>

struct nml_fw_rule {
	__u8 reserved[3];
	__u8 ip_proto;
	__u8 l4_src_port[2], l4_dst_port[2];
};

struct nml_fw_stats {
	__u64 matched;
	__u64 invalid;
};
