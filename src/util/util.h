/** netmill: utilitary functions
2024, Simon Zolin */

#include <ffbase/string.h>
#include <net/if.h>

#ifdef FF_LINUX

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
