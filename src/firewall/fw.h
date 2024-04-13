/** netmill: firewall: shared data */

#include <util/lxdp.h>

struct firewall_rule {
	uint	ip_proto;
	uint	l4_src_port, l4_dst_port;
};

struct nml_fw_maps {
	struct bpf_map *masks;
	struct bpf_map *rules;
	struct bpf_map *stats;
	struct bpf_map *xsk;
	ffvec	umasks; // struct nml_fw_rule[]
};

extern int nml_fw_maps_init(struct lxdp *lx, struct nml_fw_maps *m);

static inline void nml_fw_maps_close(struct nml_fw_maps *m)
{
	ffvec_free(&m->umasks);
}

extern int fw_rule_add(struct nml_fw_maps *m, const struct firewall_rule *rule);
