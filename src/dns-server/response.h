/** netmill: dns-server: prepare response
2023, Simon Zolin */

#include <dns-server/conn.h>

static int ds_resp_open(nml_dns_sv_conn *c)
{
	if (c->respbuf.len)
		return NMLR_SKIP;
	return NMLR_OPEN;
}

static void ds_resp_close(nml_dns_sv_conn *c)
{
	ffvec_free(&c->respbuf);
}

static int ds_resp_process(nml_dns_sv_conn *c)
{
	ffvec resp = {};
	if (NULL == ffvec_alloc(&resp, FFDNS_MAXMSG, 1))
		return NMLR_ERR;
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
	if (ff_unlikely(c->conf->log_level >= NML_LOG_DEBUG && c->conf->debug_data_dump_len)) {
		uint n = ffmin(c->respbuf.len, c->conf->debug_data_dump_len);
		ffstr sresp = ffmem_alprint(c->respbuf.ptr, n, 0);
		DS_DEBUG(c, "client: response: [%L]\n%S", c->respbuf.len, &sresp);
		ffstr_free(&sresp);
	}

	return NMLR_DONE;
}

const nml_dns_component nml_dns_response = {
	ds_resp_open, ds_resp_close, ds_resp_process,
	"resp"
};
