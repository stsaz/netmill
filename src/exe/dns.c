/** netmill: executor: start DNS server
2023, Simon Zolin */

#include <exe/shared.h>
#include <util/kq.h>
#include <util/ipaddr.h>
#include <util/ssl.h>
#include <ffsys/signal.h>
#include <ffbase/args.h>

struct dns_sv_conf {
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
};

static struct dns_sv_conf *dc;

static int dns_cmd_listen(struct dns_sv_conf *conf, ffstr val)
{
	if (0 > ffip_port_split(val, conf->listen_addr[0].ip, &conf->listen_addr[0].port))
		return R_BADVAL;
	conf->sv.server.listen_addresses = conf->listen_addr;
	return 0;
}

static int dns_cmd_hosts(struct dns_sv_conf *conf, char *fn)
{
	*ffvec_pushT(&conf->sv.hosts.filenames, char*) = fn;
	return 0;
}

static const job_if dns_serv;

static int dns_cmd_upstream(struct dns_sv_conf *conf, const char *val)
{
	conf->have_doh |= ffsz_matchz(val, "https://");
	*ffvec_pushT(&conf->sv.upstreams.upstreams, const char*) = val;
	return 0;
}

static int dns_cmd_block_mode(struct dns_sv_conf *conf, ffstr val)
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

static int dns_cmd_cache_dir(struct dns_sv_conf *conf, const char *val)
{
	conf->cache_dir = conf_abs_filename(val);
	conf->sv.filecache.dir = conf->cache_dir;
	return 0;
}

static int dns_cmd_fin(struct dns_sv_conf *conf)
{
	struct nml_dns_server_conf *sc = &conf->sv;
	sc->hosts.block_aaaa = conf->block_aaaa;
	sc->hosts.monitor_change = conf->monitor;
	sc->hosts.file_refresh_period_sec = 1*60;
	x->job = &dns_serv;
	return 0;
}

static int dns_cmd_help()
{
	static const char help[] =
"Start DNS server\n\
    netmill dns [OPTIONS]\n\
\n\
Options:\n\
  listen ADDR       Listening IP and UDP port (def: 53)\n\
                      e.g. '53' or '127.0.0.1:53' or '[::1]:53'\n\
\n\
  aaaa-block        Respond to all AAAA requests with an empty set\n\
\n\
  hosts FILE        Use 'hosts' file\n\
  block-mode STR    How to respond to requests for blocked hosts (def: local_ip):\n\
                      local_ip\n\
                      null_ip\n\
                      empty\n\
                      nxdomain\n\
                      refused\n\
                      drop\n\
  block-ttl N       TTL for blocked responses (def: 60)\n\
  rewrite-ttl N     TTL for rewritten responses (def: 60)\n\
  monitor           Auto-refresh after hosts file has been updated\n\
\n\
  cache-dir DIR     Cache directory name\n\
  min-ttl N         Minimum TTL value for a cached no-error response\n\
  error-ttl N       Minimum TTL value for a cached error response\n\
\n\
  upstream ADDR         Upstream server address:\n\
                          \"https://HOST\"  DNS/HTTPS (HOST's IP address is resolved via 'hosts' files)\n\
                          \"IP\"            DNS/UDP\n\
  read-timeout N        Response receive timeout (msec) (def: 300)\n\
  resend-attempts N     Number of request re-send attempts after timeout (def: 2)\n\
\n\
DoH:\n\
  cert FILE             Set certificate & private-key PEM file (def: client.pem)\n\
\n\
Signal handlers:\n\
  SIGHUP    Refresh lists\n\
";
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct dns_sv_conf, m)
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

static struct dns_sv_conf* dns_conf()
{
	struct dns_sv_conf *conf = ffmem_new(struct dns_sv_conf);
#ifdef FF_UNIX
	conf->kqsig = FFKQSIG_NULL;
#endif
	conf->listen_addr[0].port = 53;
	nml_dns_server_conf(NULL, &conf->sv);

	conf->sv.log_level = x->conf.log_level;
	conf->sv.log_obj = x;
	conf->sv.log = exe_log;
	conf->sv.log_date_buffer = x->log.date;

	conf->sv.hosts.block_mode = NML_DNS_BLOCK_LOCAL_IP;
	conf->sv.hosts.rewrite_ttl = 60;
	conf->sv.hosts.block_ttl = 60;

	conf->sv.upstreams.read_timeout_msec = 300;
	conf->sv.upstreams.resend_attempts = 2;

	return conf;
}

struct ffarg_ctx dns_ctx()
{
	dc = dns_conf();
	struct ffarg_ctx ax = { dns_args, dc };
	return ax;
}

static void* dns_wrk_create()
{
	nml_dns_server *s;
	if (!(s = nml_dns_server_new()))
		return NULL;
	if (nml_dns_server_conf(s, &dc->sv)) {
		nml_dns_server_free(s);
		return NULL;
	}
	return s;
}

extern int cert_pem_create(const char *fn, uint pkey_bits, struct ffssl_cert_newinfo *ci);

static struct nml_ssl_ctx* dns_sv_ssl_prepare()
{
	struct nml_ssl_ctx *sc = ffmem_new(struct nml_ssl_ctx);
	struct ffssl_ctx_conf *scc = ffmem_new(struct ffssl_ctx_conf);
	sc->ctx_conf = scc;

	if (!dc->cert_key_file) {
		dc->cert_key_file = dc->cert_key_file_buf = ffsz_allocfmt("%S/client.pem", &x->conf.root_dir);
		if (!fffile_exists(dc->cert_key_file)) {
			fftime now;
			fftime_now(&now);
			struct ffssl_cert_newinfo ci = {
				.subject = FFSTR_Z("/O=test"),
				.from_time = now.sec,
				.until_time = now.sec + 10*365*24*60*60,
			};
			cert_pem_create(dc->cert_key_file, 2048, &ci);
			infolog("generated certificate file: %s", dc->cert_key_file);
		}
	}

	scc->cert_file = dc->cert_key_file;
	scc->pkey_file = dc->cert_key_file;
	scc->allowed_protocols = FFSSL_PROTO_TLS13;

	sc->log_level = x->conf.log_level;
	sc->log_obj = x;
	sc->log = exe_log;

	if (nml_ssl_init(sc))
		return NULL;

	return sc;
}

extern void nml_http_cl_conn_cache_destroy(void *opaque, ffstr name, ffstr data);

static void* dns_sv_doh_conn_cache()
{
	struct nml_cache_conf *cconf = ffmem_new(struct nml_cache_conf);
	nml_cache_conf(NULL, cconf);

	cconf->log_level = x->conf.log_level;
	cconf->log = exe_log;
	cconf->log_obj = x;

	cconf->max_items = 60000;
	cconf->destroy = nml_http_cl_conn_cache_destroy;
	cconf->opaque = NULL;

	nml_cache_ctx *cc = nml_cache_create();
	if (!cc) return NULL;
	nml_cache_conf(cc, cconf);
	return cc;
}

extern const nml_dns_component* nml_dns_server_chain[];

static int dns_setup()
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	struct nml_dns_server_conf *sc = &dc->sv;
	sc->server.conn_id_counter = &x->conn_id;
	sc->server.reuse_port = 1;

	sc->chain = nml_dns_server_chain;

	if (dc->have_doh
		&& !(sc->upstreams.doh_ssl_ctx = dns_sv_ssl_prepare()))
		return -1;

	if (dc->have_doh
		&& !(sc->upstreams.doh_connection_cache = dns_sv_doh_conn_cache()))
		return -1;

	if (!ffvec_zallocT(&x->workers, 1, struct worker))
		return -1;
	x->workers.len = 1;
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (!(w->dns = dns_wrk_create()))
			return -1;
	}

	nml_dns_hosts_init(sc);
	nml_dns_filecache_init(sc);

	if (nml_dns_upstreams_init(sc))
		return -1;
	return 0;
}

/** Send stop signal to all workers */
static void dns_stop()
{
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (w->dns)
			nml_dns_server_stop(w->dns);
	}
}

static void dns_destroy()
{
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (w->dns)  {
			nml_dns_server_stop(w->dns);
			if (w->thd != FFTHREAD_NULL) {
				ffthread_join(w->thd, -1, NULL);
			}
		}
	}

	struct dns_sv_conf *conf = dc;
	struct nml_dns_server_conf *dsc = &conf->sv;
	nml_dns_upstreams_uninit(dsc);
	nml_dns_hosts_uninit(dsc);
	nml_cache_destroy(dsc->upstreams.doh_connection_cache);

	FFSLICE_WALK(&x->workers, w) {
#ifdef FF_UNIX
		if (w->dns)
			ffkqsig_detach(conf->kqsig, dsc->core.kq(dsc->boss));
#endif
		nml_dns_server_free(w->dns);
	}

	ffvec_free(&dsc->upstreams.upstreams);
	ffvec_free(&dsc->hosts.filenames);
	ffmem_free(conf->cache_dir);
	ffmem_free(conf);
}

#ifdef FF_UNIX
static void sig_handler(struct dns_sv_conf *conf)
{
	int sig = ffkqsig_read(conf->kqsig, NULL);
	infolog("received system signal: %d", sig);
	switch (sig) {
	case SIGHUP:
		nml_dns_hosts_refresh(&conf->sv);  break;
	}
}
#endif

static void sig_prepare(struct dns_sv_conf *conf)
{
#ifdef FF_UNIX
	static const int sigs[] = { SIGHUP };
	ffsig_mask(SIG_BLOCK, sigs, FF_COUNT(sigs));
	conf->kqsig_kev.rhandler = (void*)sig_handler;
	conf->kqsig_kev.obj = conf;
	conf->kqsig_kev.rtask.active = 1;
	if (FFKQSIG_NULL == (conf->kqsig = ffkqsig_attach(conf->sv.core.kq(conf->sv.boss), sigs, FF_COUNT(sigs), &conf->kqsig_kev)))
		syserrlog("ffkqsig_attach");
#endif
}

static int dns_run()
{
	sig_prepare(dc);

	struct worker *w = x->workers.ptr;
	if (nml_dns_server_run(w->dns))
		return -1;
	return 0;
}

static const job_if dns_serv = {
	.setup = dns_setup,
	.run = dns_run,
	.stop = dns_stop,
	.destroy = dns_destroy,
};
