/** netmill: executor: interface
2022, Simon Zolin */

#include <netmill.h>
#include <ffsys/dylib.h>
#include <util/log.h>

typedef struct job_if job_if;
struct job_if {
	int (*setup)();
	int (*run)();
	void (*stop)();
	void (*destroy)();
};

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

struct mod {
	char *name;
	ffdl dl;
	const nml_module *mif;
};

struct exe {
	struct exe_conf conf;
	struct zzlog log;

	fflock mods_lock;
	ffvec mods; // struct mod[]

	uint argi;
	const nml_operation_if *opif;
	void *op;
	const job_if *job;
};

extern struct exe *x;

extern char* conf_abs_filename(const char *rel_fn);
extern void help_info_write(const char *sz);
extern void exe_log(void *opaque, uint level, const char *ctx, const char *id, const char *fmt, ...);

#define syserrlog(...) \
	exe_log(NULL, NML_LOG_SYSERR, "exe", NULL, __VA_ARGS__)

#define errlog(...) \
	exe_log(NULL, NML_LOG_ERR, "exe", NULL, __VA_ARGS__)

#define infolog(...) \
	exe_log(NULL, NML_LOG_INFO, "exe", NULL, __VA_ARGS__)

#define dbglog(...) \
do { \
	if (x->conf.log_level >= NML_LOG_DEBUG) \
		exe_log(NULL, NML_LOG_DEBUG, "exe", NULL, __VA_ARGS__); \
} while (0)
