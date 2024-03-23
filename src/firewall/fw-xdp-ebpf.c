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

BPF_MAP_DECLARE(nml_fw_rule_map, BPF_MAP_TYPE_HASH, struct nml_fw_rule_key, struct nml_fw_rule, 16);
BPF_MAP_DECLARE(nml_fw_stats_map, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct nml_fw_stats, 1);
BPF_MAP_DECLARE(nml_fw_xsk_map, BPF_MAP_TYPE_XSKMAP, __u32, __u32, 1);

/** This program redirects matched traffic to AF_XDP socket.
Algorithm:
. Drop if not enough data in packet
. Match by Ethernet type + IPv4/IPv6 protocol/next-header + UDP/TCP ports
	or by Ethernet type + IPv4/IPv6 protocol/next-header
		(e.g. match all UDP)
	or by Ethernet type
		(e.g. match all IPv4)
. Match by Ethernet type + IPv4/IPv6 protocol/next-header + UDP/TCP destination port
. If match:
	. Redirect to AF_XDP socket
. Pass to kernel
*/
SEC("prog")
int nml_fw(struct xdp_md *ctx)
{
	const void *data_end = (void*)(long)ctx->data_end;
	const struct ethhdr *eth = (void*)(long)ctx->data;
	const void *l4;
	if ((void*)(eth + 1) > data_end)
		goto invalid; // no Ethernet header

	struct nml_fw_rule_key k;
	*(__u16*)k.eth_proto = eth->h_proto;
	k.reserved = 0;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {

		const struct iphdr *ip = (void*)(eth + 1);
		if ((void*)(ip + 1) > data_end)
			goto invalid; // no IPv4 header

		l4 = (char*)ip + ip->ihl * 4;
		if (l4 > data_end)
			goto invalid; // incomplete IPv4 header

		k.ip_proto = ip->protocol;

	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {

		const struct ipv6hdr *ip6 = (void*)(eth + 1);
		if ((void*)(ip6 + 1) > data_end)
			goto invalid; // no IPv6 header

		l4 = ip6 + 1;
		k.ip_proto = ip6->nexthdr;

	} else {
		l4 = NULL;
		k.ip_proto = 0;
	}

	if (k.ip_proto
		&& (k.ip_proto == IPPROTO_UDP
			|| k.ip_proto == IPPROTO_TCP)) {
		/*
		src[2]
		dst[2]
		*/
		if (l4 + 2 + 2 > data_end)
			goto invalid; // no UDP/TCP ports

		*(__u16*)k.l4_src_port = *(__u16*)l4;
		*(__u16*)k.l4_dst_port = *(__u16*)(l4 + 2);

	} else {
		*(__u16*)k.l4_src_port = 0;
		*(__u16*)k.l4_dst_port = 0;
	}

	struct nml_fw_rule *rule;
	if ((rule = bpf_map_lookup_elem(&nml_fw_rule_map, &k)))
		goto match;

	if (k.ip_proto == IPPROTO_UDP
		|| k.ip_proto == IPPROTO_TCP) {

		// Match by L4 destination port only
		*(__u16*)k.l4_src_port = 0;
		if ((rule = bpf_map_lookup_elem(&nml_fw_rule_map, &k)))
			goto match;
	}

	return XDP_PASS;

invalid:
	{
	__u32 key = 0;
	struct nml_fw_stats *stats = bpf_map_lookup_elem(&nml_fw_stats_map, &key);
	if (stats)
		stats->invalid++;
	return XDP_DROP;
	}

match:
	{
	__u32 key = 0;
	struct nml_fw_stats *stats = bpf_map_lookup_elem(&nml_fw_stats_map, &key);
	if (stats)
		stats->matched++;
	}
    return bpf_redirect_map(&nml_fw_xsk_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";
