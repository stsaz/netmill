/** netmill: http-server: parse HTTP request
2022, Simon Zolin */

#include <http-server/conn.h>
#include <ffsys/path.h>
#include <ffsys/perf.h>
#include <ffbase/mem-print.h>

static int hs_req_parse(nml_http_sv_conn *c);

static int hs_req_open(nml_http_sv_conn *c)
{
	c->resp.content_length = ~0ULL;
	return NMLR_OPEN;
}

static void hs_req_close(nml_http_sv_conn *c)
{
	if (c->chain_reset) {
		// preserve pipelined data
		ffstr_erase_left((ffstr*)&c->recv.req, c->req.full.len);
		c->req_unprocessed_data = !!c->recv.req.len;
	} else {
		ffvec_free(&c->recv.req);
	}
	ffstr_free(&c->req.unescaped_path);
}

static int hs_req_read(nml_http_sv_conn *c)
{
	if (c->req_unprocessed_data) {
		c->req_unprocessed_data = 0;
	}

	int r = hs_req_parse(c);
	if (r == 0) {
		c->output = c->input;
		ffstr_shift(&c->output, c->req.full.len);

		if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
			uint n = ffmin(c->output.len, c->conf->debug_data_dump_len);
			ffstr s = ffmem_alprint(c->output.ptr, n, FFMEM_PRINT_ZEROSPACE);
			HS_DEBUG(c, "\n%S", &s);
			ffstr_free(&s);
		}

		return NMLR_DONE;
	} else if (r < 0) {
		return NMLR_DONE;
	}

	if (c->recv.req.len == c->recv.req.cap) {
		HS_WARN(c, "reached `read_buf_size` limit");
		return NMLR_ERR;
	}

	return NMLR_BACK;
}

/**
Return 0 if request is complete
 >0 if need more data */
static int hs_req_parse(nml_http_sv_conn *c)
{
	char *buf = c->input.ptr;
	ffstr req = FFSTR_INITSTR(&c->input), method, url, proto;
	int r, ka = 0;

	if (c->start_time_msec == 0) {
		fftime t = c->conf->core.date(c->conf->boss, NULL);
		c->start_time_msec = fftime_to_msec(&t);
	}

	fftime t_begin;
	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG))
		t_begin = fftime_monotonic();

	r = http_req_parse(req, &method, &url, &proto);
	if (r == 0)
		return 1;
	else if (r < 0) {
		HS_WARN(c, "http_req_parse");
		goto err;
	}

	range16_set(&c->req.line, 0, r-1);
	if (req.ptr[r-2] == '\r')
		c->req.line.len--;
	ffstr_shift(&req, r);
	c->req.headers.off = req.ptr - buf;

	ffstr name = {}, val = {};
	for (;;) {
		r = http_hdr_parse(req, &name, &val);
		if (r == 0) {
			return 1;
		} else if (r < 0) {
			HS_WARN(c, "bad header");
			// HS_DEBUG(c, "full request data: %S", &c->input);
			goto err;
		}
		ffstr_shift(&req, r);

		if (r <= 2)
			break;

		switch (name.ptr[0] & ~0x20) {
		case 'A':
			if (ffstr_ieqcz(&name, "Accept-Encoding")) {
				range16_set(&c->req.accept_encoding, val.ptr - buf, val.len);
			}
			break;

		case 'H':
			if (ffstr_ieqcz(&name, "Host") && c->req.host.len == 0) {
				range16_set(&c->req.host, val.ptr - buf, val.len);
			}
			break;

		case 'C':
			if (ffstr_ieqcz(&name, "Connection")) {
				if (ffstr_ieqcz(&val, "keep-alive"))
					ka = 1;
				else if (ffstr_ieqcz(&val, "close"))
					ka = -1;
			}
			break;

		case 'I':
			if (ffstr_ieqcz(&name, "If-Modified-Since")) {
				range16_set(&c->req.if_modified_since, val.ptr - buf, val.len);
			}
			break;

		case 'U':
			if (ffstr_ieqcz(&name, "User-Agent")) {
				range16_set(&c->req.user_agent, val.ptr - buf, val.len);
			}
			break;
		}
	}

	HS_DEBUG(c, "request: [%u] %*s", (int)(req.ptr - buf), req.ptr - buf, buf);

	range16_set(&c->req.full, 0, req.ptr - buf);
	c->req.headers.len = req.ptr - buf - c->req.headers.off;

	c->resp_connection_keepalive = (proto.ptr[7] == '1');
	if (ka > 0)
		c->resp_connection_keepalive = 1;
	else if (ka < 0)
		c->resp_connection_keepalive = 0;

	if (proto.ptr[7] == '1' && c->req.host.len == 0) {
		HS_WARN(c, "no host");
		goto err;
	}

	c->req_no_chunked = (proto.ptr[7] == '0');

	struct httpurl_parts parts = {};
	httpurl_split(&parts, url);

	range16_set(&c->req.method, method.ptr - buf, method.len);
	range16_set(&c->req.url, url.ptr - buf, url.len);
	range16_set(&c->req.path, parts.path.ptr - buf, parts.path.len);
	range16_set(&c->req.querystr, parts.query.ptr - buf, parts.query.len);

	r = httpurl_unescape(NULL, 0, parts.path);
	if (NULL == ffstr_alloc(&c->req.unescaped_path, r)) {
		hs_response_err(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return -1;
	}
	r = httpurl_unescape(c->req.unescaped_path.ptr, r, parts.path);
	if (r < 0) {
		HS_WARN(c, "httpurl_unescape");
		goto err;
	}

	r = ffpath_normalize(c->req.unescaped_path.ptr, r, c->req.unescaped_path.ptr, r, FFPATH_SLASH_ONLY | FFPATH_NO_DISK_LETTER);
	if (r < 0) {
		HS_WARN(c, "ffpath_normalize");
		goto err;
	}
	c->req.unescaped_path.len = r;

	c->req_complete = !ffstr_eqz(&method, "CONNECT");

	if (ff_unlikely(c->log_level >= NML_LOG_DEBUG)) {
		fftime t_end = fftime_monotonic();
		fftime_sub(&t_end, &t_begin);
		HS_DEBUG(c, "request parsing time: %Uus", fftime_to_usec(&t_end));
	}

	return 0;

err:
	hs_response_err(c, HTTP_400_BAD_REQUEST);
	return -1;
}

const nml_http_sv_component nml_http_sv_request = {
	hs_req_open, hs_req_close, hs_req_read,
	"req-parse"
};
