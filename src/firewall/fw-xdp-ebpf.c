/** netmill: firewall: eBPF filter (kernel)
2024, Simon Zolin */

#include <firewall/data.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define BPF_MAP_DECLARE(NAME, T, K, V, MAX) \
	struct { \
		int (*type)[T]; \
		K *key; \
		V *value; \
		int (*max_entries)[MAX]; \
	} NAME \
	SEC(".maps")

BPF_MAP_DECLARE(nml_fw_mask_map, BPF_MAP_TYPE_ARRAY, __u32, struct nml_fw_rule, 16);
BPF_MAP_DECLARE(nml_fw_rule_map, BPF_MAP_TYPE_HASH, struct nml_fw_rule, __u8, 16);
BPF_MAP_DECLARE(nml_fw_stats_map, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct nml_fw_stats, 1);
BPF_MAP_DECLARE(nml_fw_xsk_map, BPF_MAP_TYPE_XSKMAP, __u32, __u32, 1);

/** This program redirects matched traffic to AF_XDP socket.
Algorithm:
- Get 3tuple (IP protocol + UDP/TCP ports) from packet
	. Drop if not enough data in packet
- For each available rule mask:
	- Apply rule mask to the 3tuple from packet
	- Find masked 3tuple in table
		. If found: Redirect to AF_XDP socket
. Pass to kernel
*/
SEC("prog")
int nml_fw(struct xdp_md *ctx)
{
	const void *data = (void*)(long)ctx->data;
	const void *data_end = (void*)(long)ctx->data_end;

	struct nml_fw_stats *stats;
	struct nml_fw_rule k_rule = {};

	const struct ethhdr *eth = data;
	data += sizeof(struct ethhdr);
	if (data > data_end)
		goto invalid; // no Ethernet header

	// Read IP proto
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		const struct iphdr *ip = data;
		data += sizeof(struct iphdr);
		if (data > data_end)
			goto invalid; // no IPv4 header

		data = (char*)ip + ip->ihl * 4;
		if (data > data_end)
			goto invalid; // incomplete IPv4 header

		k_rule.ip_proto = ip->protocol;

	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6 = data;
		data += sizeof(struct ipv6hdr);
		if (data > data_end)
			goto invalid; // no IPv6 header
		k_rule.ip_proto = ip6->nexthdr;

	} else {
		goto pass;
	}

	// Read L4 info
	const void *l4 = data;
	data += 2+2;
	if (data > data_end)
		goto invalid; // no L4 ports
	*(__u32*)k_rule.l4_src_port = *(__u32*)l4;

	for (__u32 k_mask = 0;  k_mask < 16;  k_mask++) {
		__u32 k = k_mask;
		struct nml_fw_rule *mask;
		if (!(mask = bpf_map_lookup_elem(&nml_fw_mask_map, &k)))
			break;

		struct nml_fw_rule k_rule2;
		*(__u64*)&k_rule2 = *(__u64*)&k_rule & *(__u64*)mask;

		__u8 *rule;
		if ((rule = bpf_map_lookup_elem(&nml_fw_rule_map, &k_rule2)))
			goto match;
	}

pass:
	return XDP_PASS;

invalid:
	{
	__u32 key = 0;
	if ((stats = bpf_map_lookup_elem(&nml_fw_stats_map, &key)))
		stats->invalid++;
	return XDP_DROP;
	}

match:
	{
	__u32 key = 0;
	if ((stats = bpf_map_lookup_elem(&nml_fw_stats_map, &key)))
		stats->matched++;
	}
	return bpf_redirect_map(&nml_fw_xsk_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";
