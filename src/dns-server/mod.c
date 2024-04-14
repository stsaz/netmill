/** netmill: dns-server: start DNS server
2023, Simon Zolin */

#include <netmill.h>
#include <util/ipaddr.h>
#include <util/ssl.h>
#include <util/util.h>
#include <ffsys/signal.h>
#include <ffsys/globals.h>
#include <ffbase/args.h>

static const nml_exe *exe;

#define DX_SYSERR(...) \
	exe->log(NULL, NML_LOG_SYSERR, "dns-server", NULL, __VA_ARGS__)

#define DX_ERR(...) \
	exe->log(NULL, NML_LOG_ERR, "dns-server", NULL, __VA_ARGS__)

#define DX_INFO(...) \
	exe->log(NULL, NML_LOG_INFO, "dns-server", NULL, __VA_ARGS__)

struct dns_sv_exe {
	struct nml_address listen_addr[2];
	struct nml_dns_server_conf sv;
	u_char	block_aaaa;
	u_char	monitor;
	char*	cache_dir;
	char*	cert_key_file, *cert_key_file_buf;
	uint	have_doh;

#ifdef FF_UNIX
	ffkqsig kqsig;
	struct zzkevent kqsig_kev;
#endif

	const nml_cache_if *cif;
	nml_dns_server *dns;
	uint	conn_id;
};

#define R_DONE  100
#define R_BADVAL  101

static int dns_cmd_listen(struct dns_sv_exe *conf, ffstr val)
{
	if (0 > ffip_port_split(val, conf->listen_addr[0].ip, &conf->listen_addr[0].port))
		return R_BADVAL;
	conf->sv.server.listen_addresses = conf->listen_addr;
	return 0;
}

static int dns_cmd_hosts(struct dns_sv_exe *conf, char *fn)
{
	*ffvec_pushT(&conf->sv.hosts.filenames, char*) = fn;
	return 0;
}

static int dns_cmd_upstream(struct dns_sv_exe *conf, const char *val)
{
	conf->have_doh |= ffsz_matchz(val, "https://");
	*ffvec_pushT(&conf->sv.upstreams.addresses, const char*) = val;
	return 0;
}

static int dns_cmd_block_mode(struct dns_sv_exe *conf, ffstr val)
{
	// enum NML_DNS_BLOCK
	static const char *const blockmode_str[] = {
		"empty",
		"null_ip",
		"local_ip",
		"nxdomain",
		"refused",
		"drop",
	};
	int i = ffszarr_find(blockmode_str, FF_COUNT(blockmode_str), val.ptr, val.len);
	if (i < 0)
		return R_BADVAL;
	conf->sv.hosts.block_mode = i;
	return 0;
}

static int dns_cmd_cache_dir(struct dns_sv_exe *conf, const char *val)
{
	conf->cache_dir = exe->path(val);
	conf->sv.filecache.dir = conf->cache_dir;
	return 0;
}

static int dns_cmd_fin(struct dns_sv_exe *conf)
{
	struct nml_dns_server_conf *sc = &conf->sv;
	sc->hosts.block_aaaa = conf->block_aaaa;
	sc->hosts.monitor_change = conf->monitor;
	sc->hosts.file_refresh_period_sec = 1*60;
	return 0;
}

static int dns_cmd_help()
{
	exe->print(
"Start DNS server\n\
    `netmill dns` [OPTIONS]\n\
\n\
Options:\n\
  `listen` ADDR       Listening IP and UDP port (def: 53)\n\
                      e.g. '53' or '127.0.0.1:53' or '[::1]:53'\n\
\n\
  `aaaa-block`        Respond to all AAAA requests with an empty set\n\
\n\
  `hosts` FILE        Use 'hosts' file\n\
  `block-mode` STR    How to respond to requests for blocked hosts (def: local_ip):\n\
                      local_ip\n\
                      null_ip\n\
                      empty\n\
                      nxdomain\n\
                      refused\n\
                      drop\n\
  `block-ttl` N       TTL for blocked responses (def: 60)\n\
  `rewrite-ttl` N     TTL for rewritten responses (def: 60)\n\
  `monitor`           Auto-refresh after hosts file has been updated\n\
\n\
  `cache-dir` DIR     Cache directory name\n\
  `min-ttl` N         Minimum TTL value for a cached no-error response\n\
  `error-ttl` N       Minimum TTL value for a cached error response\n\
\n\
  `upstream` ADDR         Upstream server address:\n\
                          \"https://HOST\"  DNS/HTTPS (HOST's IP address is resolved via 'hosts' files)\n\
                          \"IP[:PORT]\"     DNS/UDP\n\
  `read-timeout` N        Response receive timeout (msec) (def: 300)\n\
  `resend-attempts` N     Number of request re-send attempts after timeout (def: 2)\n\
\n\
DoH:\n\
  `cert` FILE             Set certificate & private-key PEM file (def: client.pem)\n\
\n\
Signal handlers:\n\
  SIGHUP    Refresh lists\n\
");
	return R_DONE;
}

#define O(m)  (void*)(size_t)FF_OFF(struct dns_sv_exe, m)
static const struct ffarg dns_args[] = {
	{ "aaaa-block",		'1',	O(block_aaaa) },
	{ "block-mode",		'S',	dns_cmd_block_mode },
	{ "block-ttl",		'u',	O(sv.hosts.block_ttl) },
	{ "cache-dir",		's',	dns_cmd_cache_dir },
	{ "cert",			's',	O(cert_key_file) },
	{ "error-ttl",		'u',	O(sv.filecache.error_ttl) },
	{ "help",			'1',	dns_cmd_help },
	{ "hosts",			'+s',	dns_cmd_hosts },
	{ "listen",			'S',	dns_cmd_listen },
	{ "min-ttl",		'u',	O(sv.filecache.min_ttl) },
	{ "monitor",		'1',	O(monitor) },
	{ "read-timeout",	'u',	O(sv.upstreams.read_timeout_msec) },
	{ "resend-attempts",'u',	O(sv.upstreams.resend_attempts) },
	{ "rewrite-ttl",	'u',	O(sv.hosts.rewrite_ttl) },
	{ "upstream",		'+s',	dns_cmd_upstream },
	{ "",				'1',	dns_cmd_fin },
	{}
};
#undef O

static struct dns_sv_exe* dns_conf()
{
	struct dns_sv_exe *conf = ffmem_new(struct dns_sv_exe);
#ifdef FF_UNIX
	conf->kqsig = FFKQSIG_NULL;
#endif
	conf->listen_addr[0].port = 53;
	nml_dns_server_conf(NULL, &conf->sv);

	conf->sv.log_level = exe->log_level;
	conf->sv.log_obj = NULL;
	conf->sv.log = exe->log;
	conf->sv.log_date_buffer = exe->log_date_buffer;

	conf->sv.hosts.block_mode = NML_DNS_BLOCK_LOCAL_IP;
	conf->sv.hosts.rewrite_ttl = 60;
	conf->sv.hosts.block_ttl = 60;

	conf->sv.upstreams.read_timeout_msec = 300;
	conf->sv.upstreams.resend_attempts = 2;

	return conf;
}

extern const nml_http_cl_component nml_http_cl_doh_resolve;
extern const nml_http_cl_component nml_http_cl_doh_output;

const nml_http_cl_component** doh_http_cl_chain()
{
	static const char names[][25] = {
		"http.cl_connection_cache",
		"http.cl_connect",
		"ssl.htcl_recv",
		"ssl.htcl_handshake",
		"ssl.htcl_send",
		"http.cl_request",
		"ssl.htcl_req",
		"ssl.htcl_send",
		"ssl.htcl_recv",
		"ssl.htcl_resp",
		"http.cl_response",
		"http.cl_transfer",
	};
	const nml_http_cl_component **c = ffmem_calloc(FF_COUNT(names) + 3, sizeof(nml_http_cl_component*)), **pc = c;
	*pc++ = &nml_http_cl_doh_resolve;
	uint i;
	FF_FOR(names, i) {
		*pc++ = exe->provide(names[i]);
	}
	*pc++ = &nml_http_cl_doh_output;
	*pc = NULL;
	return c;
}

static struct nml_ssl_ctx* dns_sv_ssl_prepare(struct dns_sv_exe *dx)
{
	struct nml_ssl_ctx *sc = ffmem_new(struct nml_ssl_ctx);
	struct ffssl_ctx_conf *scc = ffmem_new(struct ffssl_ctx_conf);
	sc->ctx_conf = scc;

	const nml_ssl_if *slif = dx->sv.upstreams.slif;

	if (!dx->cert_key_file) {
		dx->cert_key_file = dx->cert_key_file_buf = exe->path("client.pem");
		if (!fffile_exists(dx->cert_key_file)) {
			fftime now;
			fftime_now(&now);
			struct ffssl_cert_newinfo ci = {
				.subject = FFSTR_Z("/O=test"),
				.from_time = now.sec,
				.until_time = now.sec + 10*365*24*60*60,
			};
			slif->cert_pem_create(dx->cert_key_file, 2048, &ci);
			DX_INFO("generated certificate file: %s", dx->cert_key_file);
		}
	}

	scc->cert_file = dx->cert_key_file;
	scc->pkey_file = dx->cert_key_file;
	scc->allowed_protocols = FFSSL_PROTO_TLS13;

	sc->log_level = exe->log_level;
	sc->log_obj = NULL;
	sc->log = exe->log;

	if (slif->init(sc))
		return NULL;

	return sc;
}

static nml_cache_ctx* dns_sv_doh_conn_cache(struct dns_sv_exe *dx)
{
	struct nml_cache_conf *cc = ffmem_new(struct nml_cache_conf);
	dx->cif->conf(NULL, cc);

	cc->log_level = exe->log_level;
	cc->log = exe->log;
	cc->log_obj = NULL;

	cc->max_items = 60000;
	cc->destroy = exe->provide("http.cl_conn_cache_destroy");
	cc->opaque = NULL;

	nml_cache_ctx *cx = dx->cif->create();
	if (!cx)
		return NULL;
	dx->cif->conf(cx, cc);
	return cx;
}

extern const nml_dns_component* nml_dns_server_hosts_chain[];
extern const nml_dns_component* nml_dns_server_chain[];

static int dns_setup(struct dns_sv_exe *dx)
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	struct nml_dns_server_conf *sc = &dx->sv;
	sc->server.conn_id_counter = &dx->conn_id;
	sc->server.reuse_port = 1;

	sc->chain = nml_dns_server_hosts_chain;
	if (sc->upstreams.addresses.len)
		sc->chain = nml_dns_server_chain;

	if (dx->have_doh) {
		sc->upstreams.slif = exe->provide("ssl.ssl");
		if (!(sc->upstreams.doh_ssl_ctx = dns_sv_ssl_prepare(dx)))
			return -1;

		if (!(sc->upstreams.doh_connection_cache = dns_sv_doh_conn_cache(dx)))
			return -1;
		sc->upstreams.cif = dx->cif;

		sc->upstreams.doh_chain = doh_http_cl_chain();
		sc->upstreams.hcif = exe->provide("http.client");
	}

	sc->server.lsif = exe->provide("core.udp_listener");
	sc->server.wif = exe->provide("core.worker");

	if (!(dx->dns = nml_dns_server_create()))
		return -1;
	if (nml_dns_server_conf(dx->dns, &dx->sv))
		return -1;

	nml_dns_hosts_init(sc);
	nml_dns_filecache_init(sc);

	if (nml_dns_upstreams_init(sc))
		return -1;
	return 0;
}

#ifdef FF_UNIX
static void sig_handler(struct dns_sv_exe *conf)
{
	int sig = ffkqsig_read(conf->kqsig, NULL);
	DX_INFO("received system signal: %d", sig);
	switch (sig) {
	case SIGHUP:
		nml_dns_hosts_refresh(&conf->sv);  break;
	}
}
#endif

static void sig_prepare(struct dns_sv_exe *conf)
{
#ifdef FF_UNIX
	static const int sigs[] = { SIGHUP };
	ffsig_mask(SIG_BLOCK, sigs, FF_COUNT(sigs));
	conf->kqsig_kev.rhandler = (void*)sig_handler;
	conf->kqsig_kev.obj = conf;
	conf->kqsig_kev.rtask.active = 1;
	if (FFKQSIG_NULL == (conf->kqsig = ffkqsig_attach(conf->sv.core.kq(conf->sv.boss), sigs, FF_COUNT(sigs), &conf->kqsig_kev)))
		DX_SYSERR("ffkqsig_attach");
#endif
}

static nml_op* dns_srv_create(char **argv)
{
	struct dns_sv_exe *dx = dns_conf();

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, dns_args, dx, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
			exe->exit(0);
		else if (r == R_BADVAL)
			DX_ERR("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			DX_ERR("command line: %s\n", as.error);
		return NULL;
	}

	dx->cif = exe->provide("core.cache");
	return dx;
}

static void dns_srv_close(nml_op *op)
{
	struct dns_sv_exe *dx = op;
	nml_dns_server_free(dx->dns);
	struct nml_dns_server_conf *dsc = &dx->sv;
	nml_dns_upstreams_uninit(dsc);
	nml_dns_hosts_uninit(dsc);

	if (dx->cif)
		dx->cif->destroy(dsc->upstreams.doh_connection_cache);

#ifdef FF_UNIX
	if (dx->dns)
		ffkqsig_detach(dx->kqsig, dsc->core.kq(dsc->boss));
#endif

	ffvec_free(&dsc->upstreams.addresses);
	ffvec_free(&dsc->hosts.filenames);
	ffmem_free(dx->cache_dir);
	ffmem_free(dx);
}

static void dns_srv_run(nml_op *op)
{
	struct dns_sv_exe *dx = op;
	if (dns_setup(dx))
		return;
	sig_prepare(dx);
	if (nml_dns_server_run(dx->dns))
		return;
}

static void dns_srv_signal(nml_op *op, uint signal)
{
	struct dns_sv_exe *dx = op;
	nml_dns_server_stop(dx->dns);
}

static const struct nml_operation_if nml_op_dns_srv = {
	dns_srv_create,
	dns_srv_close,
	dns_srv_run,
	dns_srv_signal,
};


static void dns_init(const nml_exe *x)
{
	exe = x;
}

static void dns_destroy()
{
}

static const void* dns_provide(const char *name)
{
	if (ffsz_eq(name, "dns"))
		return &nml_op_dns_srv;
	return NULL;
}

NML_MOD_DEFINE(dns);
