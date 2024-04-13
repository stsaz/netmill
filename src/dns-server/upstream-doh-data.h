
/** Data shared between dns-sv.upstream_doh and http-htcl.doh components */
struct nml_doh {
	nml_dns_sv_conn *dns_conn;
	struct nml_dns_server_conf *dns_conf;
	char	buf[1024];

	struct nml_http_client_conf conf;
	nml_http_client *htcl;
	nml_task task;

	nml_timer tmr;

	uint	code;
	ffstr	status, headers;
	ffstr	body;

	uint	resp_complete :1;
	uint	signalled :1;
	uint	connection_busy :1;
};
