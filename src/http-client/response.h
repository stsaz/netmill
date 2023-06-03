/** netmill: http-client: parse HTTP response
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int nml_oresp_open(nml_http_client *c)
{
	c->response.content_length = ~0ULL;
	return NMLF_OPEN;
}

static void nml_oresp_close(nml_http_client *c)
{
}

static int nml_oresp_process(nml_http_client *c)
{
	ffstr d = c->input, proto, msg;
	uint code;
	int r = http_resp_parse(d, &proto, &code, &msg);
	if (r == 0) {
		return NMLF_BACK;
	} else if (r < 0) {
		cl_warnlog(c, "response: bad status line");
		return NMLF_ERR;
	}
	ffstr_shift(&d, r);
	uint firstline_len = r;

	int have_content_length = 0;

	for (;;) {
		ffstr name = {}, val = {};
		r = http_hdr_parse(d, &name, &val);
		if (r == 0) {
			return NMLF_BACK;
		} else if (r < 0) {
			cl_warnlog(c, "response: bad header");
			return NMLF_ERR;
		}
		ffstr_shift(&d, r);

		if (r <= 2)
			break;

		 if (ffstr_ieqcz(&name, "Transfer-Encoding")) {
			if (ffstr_imatchz(&val, "chunked")) // "chunked [; transfer-extension]"
				c->response_chunked = 1;
			c->response.content_length = ~0ULL;

		} else if (ffstr_ieqcz(&name, "Content-Length")) {
			if (have_content_length) {
				cl_warnlog(c, "duplicate Content-Length");
				return NMLF_ERR;
			}
			if (!c->response_chunked
				&& !ffstr_to_uint64(&val, &c->response.content_length)) {
				cl_warnlog(c, "bad Content-Length");
				return NMLF_ERR;
			}
			have_content_length = 1;

		} else if (ffstr_ieqcz(&name, "Connection")) {
			if (ffstr_ieqcz(&val, "close"))
				c->connection_close = 1;

		} else if (ffstr_ieqcz(&name, "Content-Type")) {
			range16_set(&c->response.content_type, val.ptr - c->input.ptr, val.len);

		} else if (ffstr_ieqcz(&name, "Location")) {
			range16_set(&c->response.location, val.ptr - c->input.ptr, val.len);
		}
	}

	c->response.code = code;
	range16_set(&c->response.status, proto.ptr+proto.len+1 - c->input.ptr, msg.ptr+msg.len - (proto.ptr+proto.len+1));
	range16_set(&c->response.msg, msg.ptr - c->input.ptr, msg.len);
	range16_set(&c->response.headers, firstline_len, d.ptr - c->input.ptr - firstline_len);

	cl_dbglog(c, "response: %*s", d.ptr - c->input.ptr, c->input.ptr);

	uint http1_1 = ffstr_eqz(&proto, "HTTP/1.1");
	if (!http1_1)
		c->connection_close = 1;
	c->output = c->input;
	ffstr_shift(&c->output, d.ptr - c->input.ptr);

	if (c->log_level >= NML_LOG_DEBUG) {
		uint n = ffmin(c->output.len, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(c->output.ptr, n, FFMEM_PRINT_ZEROSPACE);
		cl_dbglog(c, "\n%S", &s);
		ffstr_free(&s);
	}

	return NMLF_DONE;
}

const struct nml_filter nml_filter_resp = {
	(void*)nml_oresp_open, (void*)nml_oresp_close, (void*)nml_oresp_process,
	"resp-parse"
};
