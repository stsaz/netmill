/** netmill: http-server: proxy--client bridge */

enum {
	PXREQ_0,
	PXREQ_1_READY,
	PXREQ_2_LOCKED,
	PXREQ_3_MORE,
};

enum {
	PXRESP_0,
	PXRESP_1_READY,
	PXRESP_2_LOCKED,
	PXRESP_3_MORE,
	PXRESP_4_DONE,
};

/** Data shared between http-sv.proxy and http-cl.proxy components */
struct http_sv_proxy {
	nml_http_sv_conn *ic;
	struct nml_http_server_conf *svconf;

	struct nml_http_client_conf conf;
	nml_http_client *cl;
	ffstr input, output;
	nml_task task;
	uint chain_pos;

	uint code;
	ffstr msg;
	uint64 content_length;
	ffstr headers;

	uint req_state, resp_state;
	uint req_complete :1;
	uint resp_status :1;
	uint resp_complete :1;
	uint tunnel :1;
	uint signalled :1;
};
