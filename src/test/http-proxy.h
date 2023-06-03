/** netmill: http-server/proxy tester
2023, Simon Zolin */

#include <http-server/request-receive.h>
#include <http-server/request.h>
#include <http-server/proxy.h>
#include <http-server/error.h>
#include <http-server/transfer.h>
#include <http-server/response.h>
#include <http-server/response-send.h>
#include <http-server/access-log.h>
#include <http-server/keep-alive.h>

const struct nml_filter* hs_filters_proxy[] = {
	&nml_filter_receive,
	&nml_filter_request,
	// &test_http_px_input,
	&nml_filter_proxy,
	// &test_http_px_output,
	&nml_filter_error,
	&nml_filter_transfer,
	&nml_filter_response,
	&nml_filter_send,
	&nml_filter_accesslog,
	&nml_filter_keepalive,
	NULL
};

extern void cl_start(ffsock csock, const ffsockaddr *peer, uint conn_id, struct nml_http_server_conf *conf);

static void test_hs_on_accept(void *obj, ffsock csock, ffsockaddr *peer)
{
	struct tester *t = obj;
	cl_start(csock, peer, 0, &t->svconf);
}

static void test_hs_on_complete(void *obj, ffsock sk, struct zzkevent *kev)
{
	struct tester *t = obj;
	ffsock_close(sk);
	if (kev != NULL) {
		ffkcall_cancel(&kev->kcall);
		zzkq_kev_free(&t->kq, kev);
	}
}

static void test_http_proxy(struct tester *t)
{
	struct nml_http_server_conf *sc = &t->svconf;
	nml_http_server_conf(NULL, sc);

	sc->log_level = NML_LOG_EXTRA;
	sc->log = test_log;
	sc->log_obj = t;

	sc->boss = t;
	sc->core = core;
	sc->on_complete = test_hs_on_complete;

	sc->filters = hs_filters_proxy;


	struct nml_tcp_listener_conf lc;
	nml_tcp_listener_conf(NULL, &lc);

	lc.log_level = NML_LOG_EXTRA;
	lc.log = test_log;
	lc.log_obj = t;

	lc.boss = t;
	lc.core = core;
	lc.on_accept = test_hs_on_accept;

	lc.addr.port = 8080;

	t->ls = nml_tcp_listener_new();
	nml_tcp_listener_conf(t->ls, &lc);
	nml_tcp_listener_run(t->ls);
}
