/** netmill: DNS server filters
2023, Simon Zolin */

#include <dns-server/request.h>
#include <dns-server/hosts.h>
#include <dns-server/file-cache.h>
#include <dns-server/upstream.h>
#include <dns-server/response.h>
#include <dns-server/reply.h>

const struct nml_filter* nml_dns_server_filters[] = {
	&nml_filter_dns_request,
	&nml_filter_dns_hosts,
	&nml_filter_dns_file_cache_req,
	&nml_filter_dns_upstream,
	&nml_filter_dns_file_cache_resp,
	&nml_filter_dns_response,
	&nml_filter_dns_reply,
	NULL
};
