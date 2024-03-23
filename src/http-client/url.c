/** netmill: http: execute HTTP request
2023, Simon Zolin */

#include <netmill.h>
#include <util/ssl.h>
#include <util/util.h>
#include <ffbase/args.h>

extern const nml_exe *exe;

#define errlog(...) \
	exe->log(NULL, NML_LOG_ERR, "url", NULL, __VA_ARGS__)

#define infolog(...) \
	exe->log(NULL, NML_LOG_INFO, "url", NULL, __VA_ARGS__)

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
	const nml_worker_if *wif;
	struct url_conf conf;
	struct nml_wrk *w;
	nml_http_client *hc;
	nml_task task;
	fffd fd;
};

static struct url_ctx *ux;

#include <http-client/url-file-write.h>

#define R_DONE  100
#define R_BADVAL  101

static int url_input(struct url_conf *uc, ffstr val)
{
	ux->conf.input = ffsz_dupstr(&val);
	return 0;
}

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
	return 0;
}

static int url_help()
{
	exe->print(
"Execute HTTP request\n\
\n\
    `netmill url` [OPTIONS] URL\n\
\n\
URL format: [scheme://] host.com [:port] [/file]\n\
\n\
OPTIONS:\n\
\n\
SSL:\n\
  `-cert` FILE        Set certificate & private-key PEM file\n\
\n\
HTTP:\n\
  `-method` STRING    HTTP method (default: GET)\n\
  `-max_redirect`     Max redirections (default: 10)\n\
  `-print_headers`    Print HTTP response headers\n\
\n\
Output:\n\
  `-output` FILE      Set output file name\n\
  `-force`            Overwrite output file\n\
\n\
  `-help`             Show help info\n\
");
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

extern const nml_http_cl_component
	nml_http_cl_resolve,
	nml_http_cl_connection_cache,
	nml_http_cl_connect,
	nml_http_cl_io,
	nml_http_cl_send,
	nml_http_cl_recv,
	nml_http_cl_response,
	nml_http_cl_request,
	nml_http_cl_transfer,
	nml_http_cl_redir;

static const nml_http_cl_component* nml_http_cl_chain[] = {
	&nml_http_cl_resolve,
	&nml_http_cl_connect,
	&nml_http_cl_request,
	&nml_http_cl_send,
	&nml_http_cl_recv,
	&nml_http_cl_response,
	&nml_http_cl_transfer,
	&nml_http_cl_redir,
	&nml_http_cl_file_write,
	NULL
};

//@ cache
static const nml_http_cl_component** nml_http_cl_ssl_chain(const nml_exe *exe)
{
	static const struct {
		char name[20];
		const void *iface;
	} names[] = {
		{"", &nml_http_cl_resolve},
		{"", &nml_http_cl_connect},
		{"ssl.htcl_recv", NULL},
		{"ssl.htcl_handshake", NULL},
		{"ssl.htcl_send", NULL},
		{"", &nml_http_cl_request},
		{"ssl.htcl_req", NULL},
		{"ssl.htcl_send", NULL},
		{"ssl.htcl_recv", NULL},
		{"ssl.htcl_resp", NULL},
		{"", &nml_http_cl_response},
		{"", &nml_http_cl_transfer},
		{"", &nml_http_cl_redir},
		{"", &nml_http_cl_file_write},
	};

	const nml_http_cl_component **c = ffmem_calloc(FF_COUNT(names) + 1, sizeof(nml_http_cl_component)), **pc = c;
	uint i;
	FF_FOR(names, i) {
		if (names[i].iface)
			*pc++ = names[i].iface;
		else
			*pc++ = exe->provide(names[i].name);
	}
	*pc++ = NULL;
	return c;
};

static int ssl_prepare()
{
	ux->conf.hcc.slif = exe->provide("ssl.ssl");

	struct nml_ssl_ctx *sc = ffmem_new(struct nml_ssl_ctx);
	ux->conf.hcc.ssl_ctx = sc;
	struct ffssl_ctx_conf *scc = ffmem_new(struct ffssl_ctx_conf);
	sc->ctx_conf = scc;

	if (!ux->conf.cert_key_file) {
		ux->conf.cert_key_file = exe->path("client.pem");
		if (!fffile_exists(ux->conf.cert_key_file)) {
			fftime now;
			fftime_now(&now);
			struct ffssl_cert_newinfo ci = {
				.subject = FFSTR_Z("/O=test"),
				.from_time = now.sec,
				.until_time = now.sec + 10*365*24*60*60,
			};
			ux->conf.hcc.slif->cert_pem_create(ux->conf.cert_key_file, 2048, &ci);
			infolog("generated certificate file: %s", ux->conf.cert_key_file);
		}
	}

	scc->cert_file = ux->conf.cert_key_file;
	scc->pkey_file = ux->conf.cert_key_file;
	// scc->allowed_protocols = FFSSL_PROTO_TLS13;

	sc->log_level = exe->log_level;
	sc->log_obj = NULL;
	sc->log = exe->log;

	if (ux->conf.hcc.slif->init(sc))
		return -1;

	ux->conf.hcc.chain = nml_http_cl_ssl_chain(exe);
	return 0;
}

static void url_signal(nml_op *op, uint signal);

static void httpcl_complete(void *param)
{
	url_signal(param, 0);
}

static int url_setup()
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	ux->conf.hcc.log_level = exe->log_level;
	ux->conf.hcc.log_obj = NULL;
	ux->conf.hcc.log = exe->log;

	ux->conf.hcc.chain = nml_http_cl_chain;

	if (ux->conf.https
		&& ssl_prepare())
		return -1;

	ux->conf.hcc.wake = httpcl_complete;
	ux->conf.hcc.wake_param = ux;

	ux->conf.hcc.max_redirect = ux->conf.max_redirect;

	ux->w = ux->wif->create(&ux->conf.hcc.core);
	struct nml_wrk_conf wc = {
		.log_level = exe->log_level,
		.log = exe->log,
		.log_obj = NULL,
		.log_ctx = "url",
		.log_date_buffer = exe->log_date_buffer,

		.events_num = 1,
		.max_connections = 1,
		.timer_interval_msec = 100,
	};
	if (ux->wif->conf(ux->w, &wc))
		return -1;
	ux->conf.hcc.boss = ux->w;

	if (!(ux->hc = nml_http_client_create()))
		return -1;

	if (nml_http_client_conf(ux->hc, &ux->conf.hcc))
		return -1;

	return 0;
}

static void url_run2(void *param)
{
	nml_http_client_run(ux->hc);
}

static int url_run3()
{
	nml_task_set(&ux->task, url_run2, NULL);
	ux->conf.hcc.core.task(ux->conf.hcc.boss, &ux->task, 1);
	ux->wif->run(ux->conf.hcc.boss);
	return 0;
}

static nml_op* url_create(char **argv)
{
	ux = ffmem_new(struct url_ctx);
	ux->fd = FFFILE_NULL;
	ux->conf.max_redirect = 10;
	ux->wif = exe->provide("core.worker");
	nml_http_client_conf(NULL, &ux->conf.hcc);

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, url_args, &ux->conf, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
		{}
		else if (r == R_BADVAL)
			errlog("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			errlog("command line: %s\n", as.error);
		return NULL;
	}

	return ux;
}

static void url_close(nml_op *op)
{
	struct url_ctx *u = op;
	nml_http_client_free(u->hc);
	if (u->wif)
		u->wif->free(u->conf.hcc.boss);
	if (u->conf.hcc.slif)
		u->conf.hcc.slif->uninit(u->conf.hcc.ssl_ctx);
	ffmem_free(u);
}

static void url_run(nml_op *op)
{
	url_setup();
	url_run3();
}

static void url_signal(nml_op *op, uint signal)
{
	struct url_ctx *u = op;
	u->wif->stop(u->conf.hcc.boss);
}

const struct nml_operation_if nml_op_url = {
	url_create,
	url_close,
	url_run,
	url_signal,
};
