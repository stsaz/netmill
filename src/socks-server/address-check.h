/** netmill: SOCKS Server: check addresses for outbound connection
2026, Simon Zolin */

#include <socks-server/conn.h>
#include <util/ipaddr.h>

static int sksv_addrchk_open(nml_socks_sv_conn *c)
{
	if (!c->conf->allow_all_targets) {
		for (uint i = 0;  i < c->resolve.addrs.len;  i++) {
			ffip6 ip = *ffslice_itemT(&c->resolve.addrs, i, ffip6);
			int allow = 0;
			if (ffip6_v4mapped(&ip))
				allow = ffip4_public(ffip6_tov4(&ip));
			else
				allow = ffip6_public(&ip);
			if (!allow) {
				SKSV_VERBOSE(c, "connection to target address is not allowed");
				return NMLR_ERR;
			}
		}
	}
	return NMLR_SKIP;
}

const nml_socks_sv_component nml_sksv_addrchk = {
	sksv_addrchk_open, NULL, NULL,
	"addr-chk"
};
