/** netmill: http-server: [DESCRIPTION]
[YEAR], [AUTHOR] */

#include <http-server/client.h>

static int nml_[NAME]_open(nml_http_sv_conn *c)
{
	return NMLF_OPEN;
}

static void nml_[NAME]_close(nml_http_sv_conn *c)
{
}

static int nml_[NAME]_process(nml_http_sv_conn *c)
{
	return NMLF_DONE;
}

const struct nml_filter nml_filter_[NAME] = {
	(void*)nml_[NAME]_open, (void*)nml_[NAME]_close, (void*)nml_[NAME]_process,
	"[NAME]"
};
