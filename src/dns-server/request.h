/** netmill: dns-server: parse request
2023, Simon Zolin */

#include <dns-server/client.h>
#include <ffbase/mem-print.h>

static int nml_dns_req_open(nml_dns_sv_conn *c)
{
	return NMLF_OPEN;
}

static void nml_dns_req_close(nml_dns_sv_conn *c)
{
	dns_msg_destroy(&c->req);
}

static int nml_dns_req_process(nml_dns_sv_conn *c)
{
	uint port = 0;
	ffslice ip = ffsockaddr_ip_port(&c->peer, &port);
	char ipstr[FFIP6_STRLEN+1];
	if (ip.len == 4)
		ffip4_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	else
		ffip6_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	cl_dbglog(c, "client: received %u bytes from %s:%u"
		, c->reqbuf.len, ipstr, port);

	if (c->conf->log_level >= NML_LOG_DEBUG && c->conf->debug_data_dump_len) {
		uint n = ffmin(c->reqbuf.len, c->conf->debug_data_dump_len);
		ffstr sreq = ffmem_alprint(c->reqbuf.ptr, n, 0);
		cl_dbglog(c, "client: [%L]\n%S", c->reqbuf.len, &sreq);
		ffstr_free(&sreq);
	}

	if (0 > ffdns_header_read(&c->req.h, c->reqbuf)) {
		cl_warnlog(c, "ffdns_header_read");
		c->rcode = FFDNS_FORMERR;
		c->status = "client-error";
		return NMLF_DONE;
	}

	if (c->req.h.response) {
		cl_warnlog(c, "req.h.response");
		return NMLF_ERR;
	}

	if (0 > ffdns_question_read(&c->req.q, c->reqbuf)){
		cl_warnlog(c, "ffdns_question_read");
		c->rcode = FFDNS_FORMERR;
		c->status = "client-error";
		return NMLF_DONE;
	}

	if (c->req.q.clas != FFDNS_IN) {
		cl_warnlog(c, "req.q.clas == %u", c->req.q.clas);
		return NMLF_ERR;
	}

	ffstr_lower((ffstr*)&c->req.q.name);
	cl_dbglog(c, "client: request %u %S (%u)"
		, c->req.q.type, &c->req.q.name, c->req.h.id);

	return NMLF_DONE;
}

const struct nml_filter nml_filter_dns_request = {
	(void*)nml_dns_req_open, (void*)nml_dns_req_close, (void*)nml_dns_req_process,
	"req"
};
