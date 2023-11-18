/** netmill: http-server: [DESCRIPTION]
[YEAR], [AUTHOR] */

#include <http-server/client.h>

static int [NAME]_open(nml_http_sv_conn *c)
{
	return NMLF_OPEN;
}

static void [NAME]_close(nml_http_sv_conn *c)
{
}

static int [NAME]_process(nml_http_sv_conn *c)
{
	return NMLF_DONE;
}

const nml_http_sv_component nml_http_sv_[NAME] = {
	[NAME]_open, [NAME]_close, [NAME]_process,
	"[NAME]"
};
