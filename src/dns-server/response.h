/** netmill: dns-server: prepare response
2023, Simon Zolin */

#include <dns-server/client.h>

static int nml_dns_resp_open(nml_dns_sv_conn *c)
{
	if (c->respbuf.len)
		return NMLF_SKIP;
	return NMLF_OPEN;
}

static void nml_dns_resp_close(nml_dns_sv_conn *c)
{
	ffvec_free(&c->respbuf);
}

static int nml_dns_resp_process(nml_dns_sv_conn *c)
{
	ffvec resp = {};
	if (!ffvec_alloc(&resp, FFDNS_MAXMSG, 1))
		return NMLF_ERR;
	ffdns_header h = {
		.id = c->req.h.id,
		.response = 1,
		.rcode = c->rcode,
		.recursion_available = 1,
		.questions = 1,
		.answers = (c->answer.clas) ? 1 : 0,
	};
	resp.len = ffdns_header_write(resp.ptr, resp.cap, &h);
	resp.len += ffdns_question_write((char*)resp.ptr + resp.len, ffvec_unused(&resp), &c->req.q);

	if (c->answer.clas) {
		resp.len += ffdns_answer_write((char*)resp.ptr + resp.len, ffvec_unused(&resp), &c->answer);
	}

	c->respbuf = resp;
	if (c->conf->log_level >= NML_LOG_DEBUG && c->conf->debug_data_dump_len) {
		uint n = ffmin(c->respbuf.len, c->conf->debug_data_dump_len);
		ffstr sresp = ffmem_alprint(c->respbuf.ptr, n, 0);
		cl_dbglog(c, "client: response: [%L]\n%S", c->respbuf.len, &sresp);
		ffstr_free(&sresp);
	}

	return NMLF_DONE;
}

const struct nml_filter nml_filter_dns_response = {
	(void*)nml_dns_resp_open, (void*)nml_dns_resp_close, (void*)nml_dns_resp_process,
	"resp"
};
