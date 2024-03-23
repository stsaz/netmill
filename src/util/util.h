/** netmill: utilitary functions
2024, Simon Zolin */

#include <ffbase/string.h>

#define FF_FOR(static_array, i) \
	for (i = 0;  i < FF_COUNT(static_array);  i++)


struct nml_if_map {
	char name[24];
	const void *iface;
};

static inline const void* nml_if_map_find(const struct nml_if_map *map, uint n, const char *name) {
	int r = ffcharr_find_sorted_padding(map, n, sizeof(map->name), sizeof(map->iface), name, ffsz_len(name));
	if (r < 0)
		return NULL;
	return map[r].iface;
}


#ifdef FF_LINUX

#include <net/if.h>

static inline int ffnetconf_if_index(ffstr name)
{
	struct ifreq ifr;
	if (sizeof(ifr.ifr_name) == ffsz_copyn(ifr.ifr_name, sizeof(ifr.ifr_name), name.ptr, name.len)) {
		errno = EINVAL;
		return 0; // too long name
	}

	int sk = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk == -1)
		return 0;

	int r = ioctl(sk, SIOGIFINDEX, &ifr);
	close(sk);

	if (r < 0)
		return 0;
	return ifr.ifr_ifindex;
}

#endif
