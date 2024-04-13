/** netmill: dns-server: connection data
2023, Simon Zolin */

#pragma once
#include <netmill.h>
#include <util/ipaddr.h>
#include <util/dns.h>
#include <util/conveyor-static.h>

#define DS_SYSWARN(c, ...) \
	c->conf->log(c->conf->log_obj, NML_LOG_SYSWARN, "dns-sv", c->id, __VA_ARGS__)

#define DS_ERR(c, ...) \
	c->conf->log(c->conf->log_obj, NML_LOG_ERR, "dns-sv", c->id, __VA_ARGS__)

#define DS_WARN(c, ...) \
	c->conf->log(c->conf->log_obj, NML_LOG_WARN, "dns-sv", c->id, __VA_ARGS__)

#define DS_VERBOSE(c, ...) \
do { \
	if (c->conf->log_level >= NML_LOG_VERBOSE) \
		c->conf->log(c->conf->log_obj, NML_LOG_VERBOSE, "dns-sv", c->id, __VA_ARGS__); \
} while (0)

#define DS_DEBUG(c, ...) \
do { \
	if (ff_unlikely(c->conf->log_level >= NML_LOG_DEBUG)) \
		c->conf->log(c->conf->log_obj, NML_LOG_DEBUG, "dns-sv", c->id, __VA_ARGS__); \
} while (0)

#define DS_EXTRALOG(c, ...)
#ifdef NML_ENABLE_LOG_EXTRA
	#undef DS_EXTRALOG
	#define DS_EXTRALOG(c, ...) \
	do { \
		if (ff_unlikely(c->conf->log_level >= NML_LOG_DEBUG)) \
			c->conf->log(c->conf->log_obj, NML_LOG_EXTRA, "dns-sv", c->id, __VA_ARGS__); \
	} while (0)
#endif

struct dns_msg {
	ffstr data;
	int ttl;
	ffdns_header h;
	ffdns_question q;
	ffvec answers; // ffdns_answer[]
};

static inline void dns_msg_destroy(struct dns_msg *msg)
{
	ffdns_question_destroy(&msg->q);
	ffdns_answer *a;
	FFSLICE_WALK_T(&msg->answers, a, ffdns_answer) {
		ffdns_answer_destroy(a);
	}
	ffvec_free(&msg->answers);
}

struct nml_doh;
struct nml_dns_sv_conn {
	struct nml_dns_server_conf *conf;
	fftime tstart;
	ffsock sk;
	ffsockaddr peer;
	char id[12]; // "*ID"
	struct dns_msg req, resp;
	ffstr reqbuf;
	ffvec respbuf;
	ffstr respbuf_cached;
	uint rcode;
	ffdns_answer answer;
	ffip6 ip;
	const char *status;
	uint upstream_attempts;
	nml_timer ups_tmr_recv;

	struct nml_conveyor conveyor;

	/** The current data passed between components */
	ffstr input, output;

	void *upstream_active_ctx;
	struct nml_doh *doh;

	uint chain_going_back :1;
	uint chain_reset :1;
	uint resp_ready :1;
	uint upstream_resp :1;
	uint upstream_timeout :1;
	uint upstream_doh :1;
};
