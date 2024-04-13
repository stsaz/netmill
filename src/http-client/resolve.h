/** netmill: http-client: resolve host address
2023, Simon Zolin */

#include <http-client/client.h>
#include <util/ipaddr.h>

static int hc_addr_split(nml_http_client *c, ffstr *name, ffip6 *ip, uint *port)
{
	if (c->conf->proxy_host.len) {
		ffstr host = c->conf->proxy_host;
		*port = c->conf->proxy_port;
		ffip4 ip4;
		if (!ffip4_parse(&ip4, host.ptr, host.len)) {
			ffip6_v4mapped_set(ip, &ip4);
			return 'a';
		} else if (!ffip6_parse(ip, host.ptr, host.len)) {
			return 'a';
		}

		*name = host;
		return 'n';
	}

	ffstr ihost = c->conf->host;
	*port = 80;
	int r = ffip_port_split(ihost, ip, port);
	if (r < 0) {

	} else if (r & 1) {
		return 'a';
	} else {
		return -1; // no IP
	}

	ffstr sport;
	ffstr_rsplitby(&ihost, ':', name, &sport);
	if (!name->len)
		return -1; // empty host name

	if (sport.len && !ffstr_toint(&sport, port, FFS_INT16))
		return -1; // bad port

	return 'n';
}

static int hc_resolve_open(nml_http_client *c)
{
	ffstr name;
	ffip6 ip;
	uint port;
	int r = hc_addr_split(c, &name, &ip, &port);
	if (r < 0) {
		HC_WARN(c, "invalid host:port value: %S", &c->conf->host);
		return NMLR_ERR;

	} else if (r == 'a') {
		// host is an IP address
		ffip6 *ip6 = ffvec_pushT(&c->resolve.addrs, ffip6);
		*ip6 = ip;
		c->name_resolved = 1;

	} else if (r == 'n') {
		if (!(c->resolve.hostname = ffsz_dupstr(&name)))
			return NMLR_ERR;
	}

	c->resolve.port = (c->conf->server_port) ? c->conf->server_port : port;
	return NMLR_OPEN;
}

static void hc_resolve_close(nml_http_client *c)
{
	ffvec_free(&c->resolve.addrs);
	ffmem_free(c->resolve.hostname);
}

static void hc_resolve_convert(nml_http_client *c, const ffaddrinfo *a)
{
	for (const ffaddrinfo *i = a;  i;  i = i->ai_next) {

		ffip6 *ip = ffvec_pushT(&c->resolve.addrs, ffip6);

		if (i->ai_family == AF_INET) {
			const struct sockaddr_in *a4 = (void*)i->ai_addr;
			ffip6_v4mapped_set(ip, (void*)&a4->sin_addr);
		} else {
			const struct sockaddr_in6 *a6 = (void*)i->ai_addr;
			ffmem_copy(ip, &a6->sin6_addr, 16);
		}

		if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
			char buf[FFIP6_STRLEN +1];
			size_t n = ffip46_tostr(ip, buf, sizeof(buf));
			HC_DEBUG(c, "%*s", n, buf);
		}
	}
}

static int hc_resolve_process(nml_http_client *c)
{
	if (!c->name_resolved) {

		if (HC_KCQ_ACTIVE(c))
			HC_DEBUG(c, "resolve complete");

		ffaddrinfo *a = ffaddrinfo_resolve_async(c->resolve.hostname, 0, HC_KCQ_CTX(c));
		if (!a) {
			if (fferr_last() == FFKCALL_EINPROGRESS) {
				HC_VERBOSE(c, "resolving host %s...", c->resolve.hostname);
				return NMLR_ASYNC;
			}

			HC_ERR(c, "host resolve: %s: %s", c->resolve.hostname, ffaddrinfo_error(fferr_last()));
			return NMLR_ERR;
		}

		c->name_resolved = 1;

		hc_resolve_convert(c, a);
		ffaddrinfo_free(a);
	}

	c->output = c->input;
	return NMLR_DONE;
}

const nml_http_cl_component nml_http_cl_resolve = {
	hc_resolve_open, hc_resolve_close, hc_resolve_process,
	"resolve"
};
