/** netmill: dns-server: send response
2023, Simon Zolin */

#include <dns-server/client.h>
#include <ffbase/mem-print.h>

static int nml_dns_reply_open(nml_dns_sv_conn *c)
{
	return NMLF_OPEN;
}

static void nml_dns_reply_close(nml_dns_sv_conn *c)
{
}

static int nml_dns_reply_process(nml_dns_sv_conn *c)
{
	int r = ffsock_sendto(c->sk, c->respbuf.ptr, c->respbuf.len, 0, &c->peer);
	if (r < 0) {
		cl_syswarnlog(c, "ffsock_sendto");
		return NMLF_ERR;
	}

	uint port = 0;
	ffslice ip = ffsockaddr_ip_port(&c->peer, &port);
	char ipstr[FFIP6_STRLEN+1];
	if (ip.len == 4)
		ffip4_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	else
		ffip6_tostrz(ip.ptr, ipstr, sizeof(ipstr));

	cl_verblog(c, "%s %u %S (%u) %LB (%s)"
		, ipstr, c->req.q.type, &c->req.q.name, c->req.h.id, c->reqbuf.len, c->status);

	return NMLF_FIN;
}

const struct nml_filter nml_filter_dns_reply = {
	(void*)nml_dns_reply_open, (void*)nml_dns_reply_close, (void*)nml_dns_reply_process,
	"reply"
};
