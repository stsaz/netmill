/** netmill: http-client: gzip decompression
2024, Simon Zolin */

#include <netmill.h>
#include <gzip/htcl-gz-read.h>
#include <gzip/htsv-gz-write.h>

static void gzip_init(const nml_exe *x)
{
}

static void gzip_destroy()
{
}

static const void* gzip_provide(const char *name)
{
	if (ffsz_eq(name, "htcl_read"))
		return &nml_http_cl_gzread;
	else if (ffsz_eq(name, "htsv_write"))
		return &nml_http_sv_gzwrite;
	return NULL;
}

NML_MOD_DEFINE(gzip);
