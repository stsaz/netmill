/** netmill: http-client: HTTP response transfer-encoding
2023, Simon Zolin */

#include <http-client/client.h>

static int nml_hc_transfer_open(nml_http_client *c)
{	
	if (c->response_chunked) {
	} else if (c->response.content_length != ~0ULL) {
		c->transfer.size = c->response.content_length;
	}

	return NMLF_OPEN;
}

static void nml_hc_transfer_close(nml_http_client *c)
{
}

static int nml_hc_transfer_process(nml_http_client *c)
{
	if (!c->chain_going_back)
		c->transfer.data = c->input;

	if (c->response_chunked) {
		if (c->transfer.data.len == 0)
			return NMLF_BACK;
		int r = httpchunked_parse(&c->transfer.chunked, c->transfer.data, &c->output);
		if (r == -1) {
			c->resp_complete = 1;
			return NMLF_DONE;
		} else if (r < 0) {
			cl_warnlog(c, "bad chunked control data");
			return NMLF_ERR;
		}
		ffstr_shift(&c->transfer.data, r);

	} else if (c->response.content_length != ~0ULL) {
		if (c->chain_going_back) {
			if (c->recv_fin)
				return NMLF_ERR;
			return NMLF_BACK;
		}

		ffsize n = ffmin(c->transfer.data.len, c->transfer.size);
		ffstr_set(&c->output, c->transfer.data.ptr, n);
		ffstr_shift(&c->transfer.data, n);

		c->transfer.size -= n;
		if (c->transfer.size == 0) {
			c->resp_complete = 1;
			return NMLF_DONE;
		}

	} else {
		if (c->recv_fin) {
			c->resp_complete = 1;
			return NMLF_DONE;
		}
		c->output = c->transfer.data;
		c->transfer.data.len = 0;
	}

	return NMLF_FWD;
}

const struct nml_filter nml_filter_http_cl_transfer = {
	(void*)nml_hc_transfer_open, (void*)nml_hc_transfer_close, (void*)nml_hc_transfer_process,
	"transfer"
};
