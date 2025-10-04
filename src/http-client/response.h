/** netmill: http-client: parse HTTP response
2023, Simon Zolin */

#include <http-client/client.h>
#include <ffbase/mem-print.h>

static int hc_resp_open(nml_http_client *c)
{
	if (!c->input.len)
		return NMLR_ERR;
	c->response.content_length = ~0ULL;
	return NMLR_OPEN;
}

static void hc_resp_close(nml_http_client *c)
{
}

static int hc_resp_process(nml_http_client *c)
{
	const char *base = c->input.ptr;
	ffstr d = c->input, proto, msg;
	uint code;
	int r = http_resp_parse(d, &proto, &code, &msg);
	if (r == 0) {
		return NMLR_BACK;
	} else if (r < 0) {
		HC_ERR(c, "response: bad status line");
		return NMLR_ERR;
	}
	ffstr_shift(&d, r);
	uint firstline_len = r;

	int have_content_length = 0;

	for (;;) {
		ffstr name = {}, val = {};
		r = http_hdr_parse(d, &name, &val);
		if (r == 0) {
			return NMLR_BACK;
		} else if (r < 0) {
			HC_ERR(c, "response: bad header");
			return NMLR_ERR;
		}
		ffstr_shift(&d, r);

		if (r <= 2)
			break;

		switch (name.ptr[0] & ~0x20) {
		case 'C':
			if (ffstr_ieqcz(&name, "Connection")) {
				if (ffstr_ieqcz(&val, "close"))
					c->connection_close = 1;

			} else if (ffstr_ieqcz(&name, "Content-Type")) {
				range16_set(&c->response.content_type, val.ptr - base, val.len);

			} else if (ffstr_ieqcz(&name, "Content-Range")) {
				range16_set(&c->response.content_range, val.ptr - base, val.len);

			} else if (ffstr_ieqcz(&name, "Content-Length")) {
				if (have_content_length) {
					HC_ERR(c, "duplicate Content-Length");
					return NMLR_ERR;
				}
				if (!c->response_chunked
					&& !ffstr_to_uint64(&val, &c->response.content_length)) {
					HC_ERR(c, "bad Content-Length");
					return NMLR_ERR;
				}
				have_content_length = 1;

			} else if (ffstr_ieqcz(&name, "Content-Encoding")) {
				range16_set(&c->response.content_encoding, val.ptr - base, val.len);
			}
			break;

		case 'L':
			if (ffstr_ieqcz(&name, "Location")) {
				range16_set(&c->response.location, val.ptr - base, val.len);
			}
			break;

		case 'T':
			if (ffstr_ieqcz(&name, "Transfer-Encoding")) {
				if (ffstr_imatchz(&val, "chunked")) // "chunked [; transfer-extension]"
					c->response_chunked = 1;
				c->response.content_length = ~0ULL;
			}
			break;
		}
	}

	c->response.code = code;
	range16_set(&c->response.whole, 0, d.ptr - base);
	range16_set(&c->response.status, proto.ptr+proto.len+1 - base, msg.ptr+msg.len - (proto.ptr+proto.len+1));
	range16_set(&c->response.msg, msg.ptr - base, msg.len);
	range16_set(&c->response.headers, firstline_len, d.ptr - base - firstline_len);
	c->response.base = (char*)base;

	HC_DEBUG(c, "response: %*s", d.ptr - base, base);

	uint http1_1 = ffstr_eqz(&proto, "HTTP/1.1");
	if (!http1_1)
		c->connection_close = 1;
	c->output = c->input;
	ffstr_shift(&c->output, d.ptr - base);

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		uint n = ffmin(c->output.len, c->conf->debug_data_dump_len);
		ffstr s = ffmem_alprint(c->output.ptr, n, FFMEM_PRINT_ZEROSPACE);
		HC_DEBUG(c, "\n%S", &s);
		ffstr_free(&s);
	}

	return NMLR_DONE;
}

const nml_http_cl_component nml_http_cl_response = {
	hc_resp_open, hc_resp_close, hc_resp_process,
	"resp-parse"
};
