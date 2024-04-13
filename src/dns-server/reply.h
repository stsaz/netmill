/** netmill: dns-server: send response
2023, Simon Zolin */

#include <dns-server/conn.h>
#include <ffbase/mem-print.h>

static int ds_reply_open(nml_dns_sv_conn *c)
{
	return NMLR_OPEN;
}

static void ds_reply_close(nml_dns_sv_conn *c)
{
}

static int ds_reply_process(nml_dns_sv_conn *c)
{
	int r = ffsock_sendto(c->sk, c->respbuf.ptr, c->respbuf.len, 0, &c->peer);
	if (r < 0) {
		DS_SYSWARN(c, "ffsock_sendto");
		return NMLR_ERR;
	}

	uint port = 0;
	ffslice ip = ffsockaddr_ip_port(&c->peer, &port);
	char ipstr[FFIP6_STRLEN+1];
	if (ip.len == 4)
		ffip4_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	else
		ffip6_tostrz(ip.ptr, ipstr, sizeof(ipstr));

	DS_VERBOSE(c, "%s %u %S (%u) %LB (%s)"
		, ipstr, c->req.q.type, &c->req.q.name, c->req.h.id, c->reqbuf.len, c->status);

	return NMLR_FIN;
}

const nml_dns_component nml_dns_reply = {
	ds_reply_open, ds_reply_close, ds_reply_process,
	"reply"
};
