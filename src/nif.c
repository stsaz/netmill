/** netmill: network interface properties
2023, Simon Zolin */

#include <netmill.h>
#include <util/ipaddr.h>

#define i_syserrlog(i, ...) \
	i->log(i->log_obj, NML_LOG_SYSERR, "nif", NULL, __VA_ARGS__)

#if __ANDROID_API__ >= 24

#include <ifaddrs.h>

static inline int _nml_nif_info(struct nml_nif_info *i, ffvec *nifs)
{
	struct ifaddrs *ifa, *it;
	if (getifaddrs(&ifa)) {
		i_syserrlog(i, "getifaddrs");
		return -1;
	}

	for (it = ifa;  it;  it = it->ifa_next) {

		struct nml_nif *nif = ffvec_zpushT(nifs, struct nml_nif);
		ffsz_copyz(nif->name, sizeof(nif->name), it->ifa_name);

		if (!it->ifa_addr)
			continue;

		if (it->ifa_addr->sa_family == AF_INET) {
			const struct sockaddr_in *sin = (void*)it->ifa_addr;
			ffip6_v4mapped_set((void*)nif->ip, (ffip4*)&sin->sin_addr);
		} else {
			const struct sockaddr_in6 *sin = (void*)it->ifa_addr;
			ffmem_copy(nif->ip, (char*)&sin->sin6_addr, 16);
		}
	}

	freeifaddrs(ifa);
	return 0;
}

#elif defined FF_LINUX

#include <FFOS/netlink.h>

static inline int _nml_nif_info(struct nml_nif_info *i, ffvec *nifs)
{
	int rc = -1;
	ffsock nl = FFSOCK_NULL;
	void *buf = NULL;

	if (FFSOCK_NULL == (nl = ffnetlink_create(NETLINK_ROUTE, RTMGRP_LINK | RTMGRP_IPV4_IFADDR, 0))) {
		i_syserrlog(i, "ffnetlink_create");
		goto end;
	}

	if (!(buf = ffmem_alloc(1*1024*1024)))
		goto end;

	struct rtgenmsg gen = {
		.rtgen_family = AF_UNSPEC,
	};
	if (ffnetlink_send(nl, RTM_GETADDR, &gen, sizeof(gen), 1)) {
		i_syserrlog(i, "ffnetlink_send");
		goto end;
	}

	for (;;) {
		int r = ffnetlink_recv(nl, buf, 1*1024*1024);
		if (r <= 0) {
			i_syserrlog(i, "ffnetlink_recv");
			goto end;
		}
		ffstr resp = FFSTR_INITN(buf, r);

		ffstr body, val;
		struct nlmsghdr *nh;
		while ((nh = ffnetlink_next(&resp, &body))) {

			switch (nh->nlmsg_type) {
			case RTM_NEWADDR: {
				struct ifaddrmsg *ifa = (struct ifaddrmsg*)body.ptr;
				ffstr_shift(&body, sizeof(struct ifaddrmsg));

				if (!(ifa->ifa_family == AF_INET
					|| ifa->ifa_family == AF_INET6))
					continue;

				struct rtattr *attr;
				while ((attr = ffnetlink_rtattr_next(&body, &val))) {

					switch (attr->rta_type) {
					case IFA_ADDRESS: {
						struct nml_nif *nif = ffvec_zpushT(nifs, struct nml_nif);
						if (ifa->ifa_family == AF_INET)
							ffip6_v4mapped_set((void*)nif->ip, (ffip4*)val.ptr);
						else
							ffmem_copy(nif->ip, val.ptr, val.len);
					}
					}
				}
				break;
			}

			case NLMSG_ERROR:
				goto end;

			case NLMSG_DONE:
				goto done;
			}
		}
	}

done:
	rc = 0;

end:
	if (rc)
		ffvec_free(nifs);
	ffmem_free(buf);
	ffnetlink_close(nl);
	return rc;
}

#else

static inline int _nml_nif_info(struct nml_nif_info *i, ffvec *nifs)
{
	return 1;
}

#endif

int nml_nif_info(struct nml_nif_info *i)
{
	ffvec nifs = {};
	if (_nml_nif_info(i, &nifs))
		return -1;
	i->nifs = *(ffslice*)&nifs;
	ffvec_null(&nifs);
	return 0;
}
