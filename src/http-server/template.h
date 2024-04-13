/** netmill: http-server: [DESCRIPTION]
[YEAR], [AUTHOR] */

#include <http-server/conn.h>

static int hs_[NAME]_open(nml_http_sv_conn *c)
{
	return NMLR_OPEN;
}

static void hs_[NAME]_close(nml_http_sv_conn *c)
{
}

static int hs_[NAME]_process(nml_http_sv_conn *c)
{
	return NMLR_DONE;
}

const nml_http_sv_component nml_http_sv_[NAME] = {
	hs_[NAME]_open, hs_[NAME]_close, hs_[NAME]_process,
	"[NAME]"
};
