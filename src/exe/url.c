/** netmill: executor: execute HTTP request
2023, Simon Zolin */

#include <netmill.h>
#include <exe/shared.h>
#include <util/ssl.h>
#include <ffbase/args.h>

struct url_conf {
	struct nml_http_client_conf hcc;
	char*	cert_key_file;
	char*	input;
	char*	method;
	char*	output;
	u_char	force;
	u_char	print_headers;
	uint	https :1;
	uint	max_redirect;
};

struct url_ctx {
	struct url_conf conf;
	struct nml_wrk *w;
	nml_http_client *hc;
	nml_task task;
	fffd fd;
};

static struct url_ctx *ux;

#include <exe/url-file-write.h>

static int url_input(struct url_conf *uc, ffstr val)
{
	ux->conf.input = ffsz_dupstr(&val);
	return 0;
}

static const job_if url_exec;

static int url_fin(struct url_conf *uc)
{
	if (!ux->conf.output) {
		ffstr name = FFSTR_Z(ux->conf.input);
		ffstr_rsplitby(&name, '/', NULL, &name);
		if (!name.len)
			name = FFSTR_Z("index.html");
		ux->conf.output = ffsz_dupstr(&name);
	}

	if (!ux->conf.force
		&& fffile_exists(ux->conf.output)) {
		errlog("%s: file exists", ux->conf.output);
		return R_BADVAL;
	}

	ux->conf.hcc.method = (ux->conf.method) ? FFSTR_Z(ux->conf.method) : FFSTR_Z("GET");

	struct httpurl_parts up = {};
	ffstr in = FFSTR_Z(ux->conf.input);
	httpurl_split(&up, in);
	ffstr_set(&ux->conf.hcc.host, up.host.ptr, up.host.len + up.port.len);
	ffstr_set(&ux->conf.hcc.path, up.path.ptr, in.ptr+in.len - up.path.ptr);
	if ((ux->conf.https = ffstr_eqz(&up.scheme, "https://"))
		&& !up.port.len)
		ux->conf.hcc.server_port = 443;

	x->job = &url_exec;
	return 0;
}

static int url_help()
{
	static const char help[] =
"Execute HTTP request\n\
\n\
    netmill url [OPTIONS] URL\n\
\n\
URL format: [scheme://] host.com [:port] [/file]\n\
\n\
OPTIONS:\n\
\n\
SSL:\n\
  -cert FILE        Set certificate & private-key PEM file\n\
\n\
HTTP:\n\
  -method STRING    HTTP method (default: GET)\n\
  -max_redirect     Max redirections (default: 10)\n\
  -print_headers    Print HTTP response headers\n\
\n\
Output:\n\
  -output FILE      Set output file name\n\
  -force            Overwrite output file\n\
\n\
  -help             Show help info\n\
";
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct url_conf, m)
static const struct ffarg url_args[] = {
	{ "-cert",			'=s',	O(cert_key_file) },
	{ "-force",			'1',	O(force) },
	{ "-help",			'1',	url_help },
	{ "-max_redirect",	'u',	O(max_redirect) },
	{ "-method",		'=s',	O(method) },
	{ "-output",		'=s',	O(output) },
	{ "-print_headers",	'1',	O(print_headers) },
	{ "\0\1",			'S',	url_input },
	{ "",				'1',	url_fin },
	{}
};
#undef O

struct ffarg_ctx url_ctx()
{
	ux = ffmem_new(struct url_ctx);
	ux->fd = FFFILE_NULL;
	ux->conf.max_redirect = 10;
	nml_http_client_conf(NULL, &ux->conf.hcc);
	struct ffarg_ctx ax = { url_args, &ux->conf };
	return ax;
}

static int cert_pem_create(const char *fn, uint pkey_bits, struct ffssl_cert_newinfo *ci)
{
	int r = 1;
	ffvec buf = {};
	ffstr kbuf = {}, cbuf = {};
	ffssl_key *k = NULL;
	ffssl_cert *c = NULL;

	if (ffssl_key_create(&k, pkey_bits, FFSSL_PKEY_RSA))
		goto end;
	if (ffssl_key_print(k, &kbuf))
		goto end;

	fftime t;
	fftime_now(&t);
	ci->pkey = k;
	if (ffssl_cert_create(&c, ci))
		goto end;
	if (ffssl_cert_print(c, &cbuf))
		goto end;

	ffvec_addstr(&buf, &cbuf);
	ffvec_addstr(&buf, &kbuf);
	if (fffile_writewhole(fn, buf.ptr, buf.len, 0)) {
		syserrlog("file write: %s", fn);
		goto end;
	}

	r = 0;

end:
	ffvec_free(&buf);
	ffstr_free(&kbuf);
	ffstr_free(&cbuf);
	return r;
}

extern const struct nml_filter
	nml_filter_resolve,
	nml_filter_connect,
	nml_filter_http_cl_request,
	nml_filter_http_cl_send,
	nml_filter_recv,
	nml_filter_resp,
	nml_filter_http_cl_transfer,
	nml_filter_redir,
	nml_filter_ssl_send,
	nml_filter_ssl_recv,
	nml_filter_ssl_handshake,
	nml_filter_ssl_req,
	nml_filter_ssl_resp;

static const struct nml_filter *nml_http_cl_filters[] = {
	&nml_filter_resolve,
	&nml_filter_connect,
	&nml_filter_http_cl_request,
	&nml_filter_http_cl_send,
	&nml_filter_recv,
	&nml_filter_resp,
	&nml_filter_http_cl_transfer,
	&nml_filter_redir,
	&nml_filter_file_write,
	NULL
};

static const struct nml_filter *nml_http_cl_ssl_filters[] = {
	&nml_filter_resolve,
	&nml_filter_connect,
	&nml_filter_ssl_recv,
	&nml_filter_ssl_handshake,
	&nml_filter_ssl_send,
	&nml_filter_http_cl_request,
	&nml_filter_ssl_req,
	&nml_filter_ssl_send,
	&nml_filter_ssl_recv,
	&nml_filter_ssl_resp,
	&nml_filter_resp,
	&nml_filter_http_cl_transfer,
	&nml_filter_redir,
	&nml_filter_file_write,
	NULL
};

static int ssl_prepare()
{
	struct nml_ssl_ctx *sc = ffmem_new(struct nml_ssl_ctx);
	ux->conf.hcc.ssl_ctx = sc;
	struct ffssl_ctx_conf *scc = ffmem_new(struct ffssl_ctx_conf);
	sc->ctx_conf = scc;

	if (!ux->conf.cert_key_file) {
		ux->conf.cert_key_file = ffsz_allocfmt("%S/client.pem", &x->conf.root_dir);
		if (!fffile_exists(ux->conf.cert_key_file)) {
			fftime now;
			fftime_now(&now);
			struct ffssl_cert_newinfo ci = {
				.subject = FFSTR_Z("/O=test"),
				.from_time = now.sec,
				.until_time = now.sec + 10*365*24*60*60,
			};
			cert_pem_create(ux->conf.cert_key_file, 2048, &ci);
			infolog("generated certificate file: %s", ux->conf.cert_key_file);
		}
	}

	scc->cert_file = ux->conf.cert_key_file;
	scc->pkey_file = ux->conf.cert_key_file;
	// scc->allowed_protocols = FFSSL_PROTO_TLS13;

	sc->log_level = x->conf.log_level;
	sc->log_obj = x;
	sc->log = exe_log;

	if (nml_ssl_init(sc))
		return -1;

	ux->conf.hcc.filters = (void*)nml_http_cl_ssl_filters;
	return 0;
}

static void httpcl_complete(void *param)
{
	x->job->stop();
}

static int url_setup()
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	ux->conf.hcc.log_level = x->conf.log_level;
	ux->conf.hcc.log_obj = x;
	ux->conf.hcc.log = exe_log;

	ux->conf.hcc.filters = (void*)nml_http_cl_filters;

	if (ux->conf.https
		&& ssl_prepare())
		return -1;

	ux->conf.hcc.wake = httpcl_complete;
	ux->conf.hcc.wake_param = NULL;

	ux->conf.hcc.max_redirect = ux->conf.max_redirect;

	ux->w = nml_wrk_new();
	struct nml_wrk_conf wc = {
		.log_level = x->conf.log_level,
		.log = exe_log,
		.log_obj = x,
		.log_ctx = "url",
		.log_date_buffer = x->log.date,

		.events_num = 1,
		.max_connections = 1,
		.timer_interval_msec = 100,
	};
	if (nml_wrk_conf(ux->w, &wc))
		return -1;
	ux->conf.hcc.core = nml_wrk_core_if;
	ux->conf.hcc.boss = ux->w;

	if (!(ux->hc = nml_http_client_new()))
		return -1;

	if (nml_http_client_conf(ux->hc, &ux->conf.hcc))
		return -1;

	return 0;
}

static void url_stop()
{
	nml_wrk_stop(ux->conf.hcc.boss);
}

static void url_destroy()
{
	if (!ux) return;

	nml_http_client_free(ux->hc);

	nml_wrk_free(ux->conf.hcc.boss);
	nml_ssl_uninit(ux->conf.hcc.ssl_ctx);
}

static void url_run2(void *param)
{
	nml_http_client_run(ux->hc);
}

static int url_run()
{
	nml_task_set(&ux->task, url_run2, NULL);
	nml_wrk_core_if.task(ux->conf.hcc.boss, &ux->task, 1);
	nml_wrk_run(ux->conf.hcc.boss);
	return 0;
}

static const job_if url_exec = {
	.setup = url_setup,
	.run = url_run,
	.stop = url_stop,
	.destroy = url_destroy,
};
