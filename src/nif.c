/** netmill: network interface properties
2023, Simon Zolin */

#include <netmill.h>
#include <util/ipaddr.h>
#include <util/ethernet.h>
#include <ffsys/netconf.h>
#include <ffsys/std.h>
// #include <ffsys/globals.h>

const nml_exe *exe;
#define IF_ERR(i, ...) \
	i->log(i->log_obj, NML_LOG_ERR, "nif", NULL, __VA_ARGS__)

int nml_nif_info(struct nml_nif_info *i, ffslice *_nifs)
{
	ffnetconf *nc = ffmem_new(ffnetconf);
	if (ffnetconf_get(nc, FFNETCONF_INTERFACES)) {
		IF_ERR(i, "%s", ffnetconf_error(nc));
		ffnetconf_destroy(nc);
		ffmem_free(nc);
		return -1;
	}
	*_nifs = *(ffslice*)&nc->ifs;
	i->nc = nc;
	return 0;
}

void nml_nif_info_destroy(struct nml_nif_info *i)
{
	ffnetconf_destroy(i->nc);
	ffmem_free(i->nc);
}

static nml_op* if_create(char **argv)
{
	return (void*)1;
}
static void if_close(nml_op *op){}
static void if_run(nml_op *op)
{
	struct nml_nif_info i = {
		.log_level = exe->log_level,
		.log = exe->log,
	};
	ffslice nifs = {};
	if (nml_nif_info(&i, &nifs))
		return;

	struct ffnetconf_ifinfo *nif, **pnif;
	FFSLICE_WALK(&nifs, pnif) {
		nif = *pnif;

		char mac_s[ETH_STRLEN+1];
		int r = eth_str(nif->hwaddr, mac_s, sizeof(mac_s));
		mac_s[r] = '\0';

		ffstdout_fmt("[%u] %s  %s\n"
			, nif->index, nif->name, mac_s);

		for (uint i = 0;  i < nif->ip_n;  i++) {
			char ip_s[FFIP6_STRLEN+1];
			r = ffip46_tostr((ffip6*)nif->ip[i], ip_s, sizeof(ip_s));
			ip_s[r] = '\0';
			ffstdout_fmt("  %s\n", ip_s);
		}
	}

	nml_nif_info_destroy(&i);
}
static void if_signal(nml_op *op, uint signal)
{
}

static const struct nml_operation_if nml_op_if = {
	if_create,
	if_close,
	if_run,
	if_signal,
};


static void nif_init(const nml_exe *x)
{
	exe = x;
}

static void nif_destroy()
{
}

static const void* nif_provide(const char *name)
{
	if (ffsz_eq(name, "if"))
		return &nml_op_if;
	return NULL;
}

NML_MOD_DEFINE(nif);
