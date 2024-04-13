/** netmill: http-client: HTTP response transfer-encoding
2023, Simon Zolin */

#include <http-client/client.h>

static int hc_transfer_open(nml_http_client *c)
{	
	if (c->response_chunked) {
	} else if (c->response.content_length != ~0ULL) {
		c->transfer.size = c->response.content_length;
	}

	return NMLR_OPEN;
}

static void hc_transfer_close(nml_http_client *c)
{
}

static int hc_transfer_process(nml_http_client *c)
{
	if (!c->chain_going_back)
		c->transfer.data = c->input;

	if (c->response_chunked) {
		if (c->transfer.data.len == 0)
			return NMLR_BACK;
		int r = httpchunked_parse(&c->transfer.chunked, c->transfer.data, &c->output);
		if (r == -1) {
			c->resp_complete = 1;
			return NMLR_DONE;
		} else if (r < 0) {
			HC_WARN(c, "bad chunked control data: %d", r);
			return NMLR_ERR;
		}
		ffstr_shift(&c->transfer.data, r);

	} else if (c->response.content_length != ~0ULL) {
		if (c->chain_going_back) {
			if (c->recv_fin)
				return NMLR_ERR;
			return NMLR_BACK;
		}

		size_t n = ffmin(c->transfer.data.len, c->transfer.size);
		ffstr_set(&c->output, c->transfer.data.ptr, n);
		ffstr_shift(&c->transfer.data, n);

		c->transfer.size -= n;
		if (c->transfer.size == 0) {
			c->resp_complete = 1;
			return NMLR_DONE;
		}

	} else {
		if (c->recv_fin) {
			c->resp_complete = 1;
			return NMLR_DONE;
		}
		if (c->chain_going_back) {
			return NMLR_BACK;
		}
		c->output = c->transfer.data;
		c->transfer.data.len = 0;
	}

	return NMLR_FWD;
}

const nml_http_cl_component nml_http_cl_transfer = {
	hc_transfer_open, hc_transfer_close, hc_transfer_process,
	"transfer"
};
