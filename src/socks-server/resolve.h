/** netmill: SOCKS Server: resolve host
2026, Simon Zolin */

#include <socks-server/conn.h>
#include <util/ipaddr.h>

static int sksv_resolve_open(nml_socks_sv_conn *c)
{
	return (c->resolve.addrs.len) ? NMLR_SKIP : NMLR_OPEN;
}

static void sksv_resolve_close(nml_socks_sv_conn *c)
{
	ffvec_free(&c->resolve.addrs);
}

static void sksv_resolve_convert(nml_socks_sv_conn *c, const ffaddrinfo *a)
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
			SKSV_DEBUG(c, "%*s", n, buf);
		}
	}
}

static int sksv_resolve_process(nml_socks_sv_conn *c)
{
	if (SKSV_KCQ_ACTIVE(c))
		SKSV_DEBUG(c, "resolve complete");

	ffaddrinfo *a = ffaddrinfo_resolve_async(c->resolve.hostname, 0, SKSV_KCQ_CTX(c));
	if (!a) {
		if (fferr_last() == FFKCALL_EINPROGRESS) {
			SKSV_VERBOSE(c, "resolving host %s...", c->resolve.hostname);
			return NMLR_ASYNC;
		}

		SKSV_ERR(c, "host resolve: %s: %s", c->resolve.hostname, ffaddrinfo_error(fferr_last()));
		sksv_response_err(c, 1);
		return NMLR_DONE;
	}

	sksv_resolve_convert(c, a);
	ffaddrinfo_free(a);

	c->output = c->input;
	return NMLR_DONE;
}

const nml_socks_sv_component nml_sksv_resolve = {
	sksv_resolve_open, sksv_resolve_close, sksv_resolve_process,
	"resolve"
};
