/** netmill: executor: dns: process command-line arguments
2023, Simon Zolin */

struct dns_sv_conf {
	struct nml_address listen_addr[2];
	struct nml_dns_server_conf sv;
	ffbyte block_aaaa;
};

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

static int dns_cmd_fin(struct dns_sv_conf *conf)
{
	conf->sv.hosts.block_aaaa = conf->block_aaaa;
	nml_dns_hosts_init(&conf->sv);
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
\n\
  upstream ADDR         Upstream server address\n\
  read-timeout N        Response receive timeout (msec) (def: 300)\n\
  resend-attempts N     Number of request re-send attempts after timeout (def: 2)\n\
";
	ffstdout_write(help, FFS_LEN(help));
	return R_DONE;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct dns_sv_conf, m)
static const struct ffarg dns_args[] = {
	{ "aaaa-block",		'1',	O(block_aaaa) },
	{ "block-mode",		'S',	dns_cmd_block_mode },
	{ "block-ttl",		'u',	O(sv.hosts.block_ttl) },
	{ "help",			'1',	dns_cmd_help },
	{ "hosts",			'+s',	dns_cmd_hosts },
	{ "listen",			'S',	dns_cmd_listen },
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
	x->conf.dns = dns_conf();
	struct ffarg_ctx ax = { dns_args, x->conf.dns };
	return ax;
}

static void* dns_wrk_create()
{
	nml_dns_server *s;
	if (!(s = nml_dns_server_new()))
		return NULL;
	if (nml_dns_server_conf(s, &x->conf.dns->sv)) {
		nml_dns_server_free(s);
		return NULL;
	}
	return s;
}

extern const struct nml_filter* nml_dns_server_filters[];

static int dns_setup()
{
	if (ffsock_init(FFSOCK_INIT_SIGPIPE | FFSOCK_INIT_WSA | FFSOCK_INIT_WSAFUNCS))
		return -1;

	struct nml_dns_server_conf *sc = &x->conf.dns->sv;
	sc->server.conn_id_counter = &x->conn_id;
	sc->server.reuse_port = 1;

	sc->filters = (void*)nml_dns_server_filters;

	if (!ffvec_zallocT(&x->workers, 1, struct worker))
		return -1;
	x->workers.len = 1;
	struct worker *w;
	FFSLICE_WALK(&x->workers, w) {
		if (!(w->dns = dns_wrk_create()))
			return -1;
	}

	if (nml_dns_upstreams_init(&x->conf.dns->sv))
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

	struct dns_sv_conf *conf = x->conf.dns;
	nml_dns_upstreams_uninit(&conf->sv);
	nml_dns_hosts_uninit(&conf->sv);

	FFSLICE_WALK(&x->workers, w) {
		nml_dns_server_free(w->dns);
	}

	ffvec_free(&conf->sv.upstreams.upstreams);
	ffvec_free(&conf->sv.hosts.filenames);
	ffmem_free(conf);
}

static int dns_run()
{
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
