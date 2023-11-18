/** netmill: http-client tester
2023, Simon Zolin */

#include <http-client/client.h>

static int test_hi_open(nml_http_client *c) { return NMLF_OPEN; }
static int test_hi_process(nml_http_client *c)
{
	struct tester *t = c->conf->wake_param;
	switch (t->test_num) {
	default:
		break;
	case 4:
		ffstr_setz(&c->output, "input-data\n");
		break;
	}

	c->req_complete = 1;
	return NMLF_DONE;
}
static const nml_component test_http_input = {
	(void*)test_hi_open, NULL, (void*)test_hi_process,
	"test-input"
};


static int test_ho_open(nml_http_client *c) { return NMLF_OPEN; }
static int test_ho_process(nml_http_client *c)
{
	struct tester *t = c->conf->wake_param;
	switch (t->test_num) {
	case 1:
		xstr(c->input, ""); break;
	case 2:
		xstr(c->input, "hello\n"); break;
	case 3:
		switch (t->test_data++) {
		case 0:
			xstr(c->input, "he"); break;
		case 1:
			xstr(c->input, "llo"); break;
		}
		break;
	case 4:
		x(c->response.code == 500);
		xstr(c->input, "error\n");
		break;
	case 5:
		xstr(c->input, "output-data\n");
		c->resp_complete = 1;
		break;
	case 6:
		c->resp_complete = 1;
		break;
	case 7:
		switch (t->test_data++) {
		case 0:
			xstr(c->input, "/redirect");
			ffsock_close(c->sk);  c->sk = FFSOCK_NULL;
			ffthread_sleep(500);
			return NMLF_FWD;
		case 1:
			xstr(c->input, "redirect successful\n"); break;
		}
		break;
	}

	if (!c->resp_complete)
		return NMLF_BACK;

	zzkq_tq_post(&t->kq_tq, &t->tsk);
	return NMLF_FIN;
}
static const nml_component test_http_output = {
	(void*)test_ho_open, NULL, (void*)test_ho_process,
	"test-output"
};


#include <http-client/resolve.h>
#include <http-client/connect.h>
#include <http-client/io.h>
#include <http-client/request.h>
#include <http-client/request-send.h>
#include <http-client/response-receive.h>
#include <http-client/response.h>
#include <http-client/transfer.h>
#include <http-client/redirect.h>

static const nml_component* hc_filters[] = {
	&test_http_input,
	&nml_http_cl_resolve,
	&nml_http_cl_connect,
	&nml_http_cl_request,
	&nml_http_cl_send,
	&nml_http_cl_recv,
	&nml_http_cl_response,
	&nml_http_cl_transfer,
	&test_http_output,
	&nml_http_cl_redir,
	NULL
};
static const nml_component* hc_tun_filters[] = {
	&test_http_input,
	&nml_http_cl_resolve,
	&nml_http_cl_connect,
	&nml_http_cl_io,
	&test_http_output,
	NULL
};

void test_hc_wake(struct tester *t)
{
	x(t->oc->resp_complete);
}

static void test_http_client(struct tester *t)
{
	t->test_data = 0;

	struct nml_http_client_conf *cc = &t->conf;
	nml_http_client_conf(NULL, cc);

	cc->log_level = NML_LOG_EXTRA;
	cc->log = test_log;
	cc->log_obj = t;

	cc->boss = t;
	cc->core = core;

	cc->wake_param = t;
	cc->wake = (void*)test_hc_wake;

	cc->filters = hc_filters;

	cc->host = FFSTR_Z("localhost:8080");
	cc->method = FFSTR_Z("GET");
	cc->headers = FFSTR_Z("Header: Value\r\n");
	switch (t->test_num) {
	case 1:
	case 2:
		cc->path = FFSTR_Z("/");
		break;
	case 3:
		cc->path = FFSTR_Z("/chunked");
		break;
	case 4:
		cc->path = FFSTR_Z("/500");
		break;
	case 5:
		cc->filters = hc_tun_filters;
		break;
	case 6:
		cc->path = FFSTR_Z("/proxy");
		cc->proxy_host = FFSTR_Z("localhost");
		cc->proxy_port = 8080;
		break;
	case 7:
		cc->path = FFSTR_Z("/302");
		cc->max_redirect = 1;
		break;
	}

	t->oc = nml_http_client_new();
	nml_http_client_conf(t->oc, cc);
	nml_http_client_run(t->oc);
}
