/** netmill: executor: interface
2022, Simon Zolin */

#include <netmill.h>
#include <util/kcq.h>
#include <util/log.h>

typedef struct job_if job_if;
struct job_if {
	int (*setup)();
	int (*run)();
	void (*stop)();
	void (*destroy)();
};

struct dns_sv_conf;
struct svc_conf;
struct exe_conf {
	uint log_level;
	ffstr root_dir;
	uint fd_limit;
	const char *log_fn;
	struct svc_conf *svc;
};

#define R_DONE  100
#define R_BADVAL  101

struct worker {
	nml_http_server *http;
	nml_dns_server *dns;
	ffthread thd;
};

struct exe {
	struct exe_conf conf;
	ffvec workers; // struct worker[]
	uint conn_id;
	struct zzlog log;
	struct zzkcq kcq;

	const job_if *job;
};

extern struct exe *x;

extern char* conf_abs_filename(const char *rel_fn);

extern void exe_log(void *opaque, uint level, const char *ctx, const char *id, const char *fmt, ...);

#define syserrlog(...) \
	exe_log(x, NML_LOG_SYSERR, "netmill", NULL, __VA_ARGS__)

#define errlog(...) \
	exe_log(x, NML_LOG_ERR, "netmill", NULL, __VA_ARGS__)

#define infolog(...) \
	exe_log(x, NML_LOG_INFO, "netmill", NULL, __VA_ARGS__)

#define dbglog(...) \
do { \
	if (x->conf.log_level >= NML_LOG_DEBUG) \
		exe_log(x, NML_LOG_DEBUG, "netmill", NULL, __VA_ARGS__); \
} while (0)

extern struct ffarg_ctx cert_ctx();
extern struct ffarg_ctx dns_ctx();
extern struct ffarg_ctx http_ctx();
extern struct ffarg_ctx url_ctx();
