/** netmill: DNS server component chain
2023, Simon Zolin */

#include <dns-server/request.h>
#include <dns-server/hosts.h>
#include <dns-server/file-cache.h>
#include <dns-server/upstream-mgr.h>
#include <dns-server/upstream-udp.h>
#include <dns-server/upstream-doh.h>
#include <dns-server/response.h>
#include <dns-server/reply.h>

const nml_dns_component* nml_dns_server_hosts_chain[] = {
	&nml_dns_request,
	&nml_dns_hosts,
	&nml_dns_response,
	&nml_dns_reply,
	NULL
};

const nml_dns_component* nml_dns_server_chain[] = {
	&nml_dns_request,
	&nml_dns_hosts,
	&nml_dns_file_cache_req,
	&nml_dns_upstream,
	&nml_dns_upstream_doh,
	&nml_dns_upstream_udp,
	&nml_dns_file_cache_resp,
	&nml_dns_response,
	&nml_dns_reply,
	NULL
};
