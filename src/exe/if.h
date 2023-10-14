/** netmill: executor: show network interfaces
2023, Simon Zolin */

#include <util/ipaddr.h>

static int nif_info()
{
	struct nml_nif_info i = {
		.log_level = x->conf.log_level,
		.log = exe_log,
	};
	nml_nif_info(&i);

	struct nml_nif *nif;
	FFSLICE_WALK(&i.nifs, nif) {
		char buf[100];
		int r = ffip46_tostr((void*)nif->ip, buf, sizeof(buf));
		buf[r] = '\0';
		ffstdout_fmt("%s\n", buf);
	}

	nml_nif_info_destroy(&i);
	return R_DONE;
}
