/** netmill: http-server: parse HTTP request
2022, Simon Zolin */

#include <http-server/client.h>
#include <FFOS/path.h>
#include <FFOS/perf.h>
#include <ffbase/mem-print.h>

static int nml_req_parse(nml_http_sv_conn *c);

static int nml_req_open(nml_http_sv_conn *c)
{
	c->resp.content_length = (ffuint64)-1;
	return NMLF_OPEN;
}

static void nml_req_close(nml_http_sv_conn *c)
{
	if (c->chain_reset) {
		// preserve pipelined data
		ffstr_erase_left((ffstr*)&c->recv.req, c->req.full.len);
		c->req_unprocessed_data = (c->recv.req.len != 0);
	} else {
		ffvec_free(&c->recv.req);
	}
	ffstr_free(&c->req.unescaped_path);
}

static int nml_req_read(nml_http_sv_conn *c)
{
	if (c->req_unprocessed_data) {
		c->req_unprocessed_data = 0;
	}

	int r = nml_req_parse(c);
	if (r == 0) {
		c->output = c->input;
		ffstr_shift(&c->output, c->req.full.len);

		if (c->log_level >= NML_LOG_DEBUG) {
			uint n = ffmin(c->output.len, c->conf->debug_data_dump_len);
			ffstr s = ffmem_alprint(c->output.ptr, n, FFMEM_PRINT_ZEROSPACE);
			cl_dbglog(c, "\n%S", &s);
			ffstr_free(&s);
		}

		return NMLF_DONE;
	} else if (r < 0) {
		return NMLF_DONE;
	}

	if (c->recv.req.len == c->recv.req.cap) {
		cl_warnlog(c, "reached `read_buf_size` limit");
		return NMLF_ERR;
	}

	return NMLF_BACK;
}

/**
Return 0 if request is complete
 >0 if need more data */
static int nml_req_parse(nml_http_sv_conn *c)
{
	char *buf = c->input.ptr;
	ffstr req = FFSTR_INITSTR(&c->input), method, url, proto;
	int r, ka = 0;

	if (c->start_time_msec == 0) {
		fftime t = c->conf->core.date(c->conf->boss, NULL);
		c->start_time_msec = fftime_to_msec(&t);
	}

	fftime t_begin;
	if (c->log_level >= NML_LOG_DEBUG)
		t_begin = fftime_monotonic();

	r = http_req_parse(req, &method, &url, &proto);
	if (r == 0)
		return 1;
	else if (r < 0) {
		cl_warnlog(c, "http_req_parse");
		goto err;
	}

	range16_set(&c->req.line, 0, r-1);
	if (req.ptr[r-2] == '\r')
		c->req.line.len--;
	ffstr_shift(&req, r);

	ffstr name = {}, val = {};
	for (;;) {
		r = http_hdr_parse(req, &name, &val);
		if (r == 0) {
			return 1;
		} else if (r < 0) {
			cl_warnlog(c, "bad header");
			// cl_dbglog(c, "full request data: %S", &c->input);
			goto err;
		}
		ffstr_shift(&req, r);

		if (r <= 2)
			break;

		if (ffstr_ieqcz(&name, "Host") && c->req.host.len == 0) {
			range16_set(&c->req.host, val.ptr - buf, val.len);

		} else if (ffstr_ieqcz(&name, "Connection")) {
			if (ffstr_ieqcz(&val, "keep-alive"))
				ka = 1;
			else if (ffstr_ieqcz(&val, "close"))
				ka = -1;

		} else if (ffstr_ieqcz(&name, "If-Modified-Since")) {
			range16_set(&c->req.if_modified_since, val.ptr - buf, val.len);
		}
	}

	cl_dbglog(c, "request: [%u] %*s", (int)(req.ptr - buf), req.ptr - buf, buf);

	range16_set(&c->req.full, 0, req.ptr - buf);

	c->resp_connection_keepalive = (proto.ptr[7] == '1');
	if (ka > 0)
		c->resp_connection_keepalive = 1;
	else if (ka < 0)
		c->resp_connection_keepalive = 0;

	if (proto.ptr[7] == '1' && c->req.host.len == 0) {
		cl_warnlog(c, "no host");
		goto err;
	}

	struct httpurl_parts parts = {};
	httpurl_split(&parts, url);

	range16_set(&c->req.method, method.ptr - buf, method.len);
	range16_set(&c->req.url, url.ptr - buf, url.len);
	range16_set(&c->req.path, parts.path.ptr - buf, parts.path.len);
	range16_set(&c->req.querystr, parts.query.ptr - buf, parts.query.len);

	r = httpurl_unescape(NULL, 0, parts.path);
	if (NULL == ffstr_alloc(&c->req.unescaped_path, r)) {
		cl_resp_status(c, HTTP_500_INTERNAL_SERVER_ERROR);
		return -1;
	}
	r = httpurl_unescape(c->req.unescaped_path.ptr, r, parts.path);
	if (r < 0) {
		cl_warnlog(c, "httpurl_unescape");
		goto err;
	}

	r = ffpath_normalize(c->req.unescaped_path.ptr, r, c->req.unescaped_path.ptr, r, FFPATH_SLASH_ONLY | FFPATH_NO_DISK_LETTER);
	if (r < 0) {
		cl_warnlog(c, "ffpath_normalize");
		goto err;
	}
	c->req.unescaped_path.len = r;

	c->req_complete = !ffstr_eqz(&method, "CONNECT");

	if (c->log_level >= NML_LOG_DEBUG) {
		fftime t_end = fftime_monotonic();
		fftime_sub(&t_end, &t_begin);
		cl_dbglog(c, "request parsing time: %Uus", fftime_to_usec(&t_end));
	}

	return 0;

err:
	cl_resp_status(c, HTTP_400_BAD_REQUEST);
	return -1;
}

const struct nml_filter nml_filter_request = {
	(void*)nml_req_open, (void*)nml_req_close, (void*)nml_req_read,
	"req-parse"
};
