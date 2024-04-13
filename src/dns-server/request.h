/** netmill: dns-server: parse request
2023, Simon Zolin */

#include <dns-server/conn.h>
#include <ffbase/mem-print.h>

static int ds_req_open(nml_dns_sv_conn *c)
{
	return NMLR_OPEN;
}

static void ds_req_close(nml_dns_sv_conn *c)
{
	dns_msg_destroy(&c->req);
}

static int ds_req_process(nml_dns_sv_conn *c)
{
	uint port = 0;
	ffslice ip = ffsockaddr_ip_port(&c->peer, &port);
	char ipstr[FFIP6_STRLEN+1];
	if (ip.len == 4)
		ffip4_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	else
		ffip6_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	DS_DEBUG(c, "client: received %u bytes from %s:%u"
		, c->reqbuf.len, ipstr, port);

	if (ff_unlikely(c->conf->log_level >= NML_LOG_DEBUG && c->conf->debug_data_dump_len)) {
		uint n = ffmin(c->reqbuf.len, c->conf->debug_data_dump_len);
		ffstr sreq = ffmem_alprint(c->reqbuf.ptr, n, 0);
		DS_DEBUG(c, "client: [%L]\n%S", c->reqbuf.len, &sreq);
		ffstr_free(&sreq);
	}

	if (0 > ffdns_header_read(&c->req.h, c->reqbuf)) {
		DS_WARN(c, "ffdns_header_read");
		c->rcode = FFDNS_FORMERR;
		c->status = "client-error";
		return NMLR_DONE;
	}

	if (c->req.h.response) {
		DS_WARN(c, "req.h.response");
		return NMLR_ERR;
	}

	if (0 > ffdns_question_read(&c->req.q, c->reqbuf)){
		DS_WARN(c, "ffdns_question_read");
		c->rcode = FFDNS_FORMERR;
		c->status = "client-error";
		return NMLR_DONE;
	}

	if (c->req.q.clas != FFDNS_IN) {
		DS_WARN(c, "req.q.clas == %u", c->req.q.clas);
		return NMLR_ERR;
	}

	ffstr_lower((ffstr*)&c->req.q.name);
	DS_DEBUG(c, "client: request %u %S (%u)"
		, c->req.q.type, &c->req.q.name, c->req.h.id);

	return NMLR_DONE;
}

const nml_dns_component nml_dns_request = {
	ds_req_open, ds_req_close, ds_req_process,
	"req"
};
