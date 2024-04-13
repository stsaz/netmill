/** netmill: ssl: extern functions
2023, Simon Zolin */

#include <netmill.h>
#include <util/ssl.h>

#define SL_ERR(c, ...) \
	c->log(c->log_obj, NML_LOG_ERR, "ssl", NULL, __VA_ARGS__)

void nml_ssl_uninit(struct nml_ssl_ctx *ctx)
{
	if (!ctx) return;

	ffssl_ctx_free(ctx->ctx);
	ffssl_uninit();
}

int nml_ssl_init(struct nml_ssl_ctx *ctx)
{
	int r;
	if ((r = ffssl_init()))
		return -1;
	if ((r = ffssl_ctx_create((ffssl_ctx**)&ctx->ctx)))
		goto err;
	if ((r = ffssl_ctx_conf(ctx->ctx, ctx->ctx_conf)))
		goto err;
	return 0;

err:
	{
	char e[1000];
	SL_ERR(ctx, "nml_ssl_init: %s", ffssl_error(r, e, sizeof(e)));
	}
	nml_ssl_uninit(ctx);
	return -1;
}
