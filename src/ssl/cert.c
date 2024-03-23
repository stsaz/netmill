/** netmill: ssl: generate certificate file
2023, Simon Zolin */

#include <netmill.h>
#include <util/ssl.h>
#include <ffsys/random.h>
#include <ffbase/args.h>

extern const nml_exe *exe;

#define syserrlog(...) \
	exe->log(NULL, NML_LOG_SYSERR, "cert", NULL, __VA_ARGS__)

#define errlog(...) \
	exe->log(NULL, NML_LOG_ERR, "cert", NULL, __VA_ARGS__)

#define infolog(...) \
	exe->log(NULL, NML_LOG_INFO, "cert", NULL, __VA_ARGS__)

struct cert_conf {
	char*	output;
	ffstr	from;
	ffstr	subject;
	ffstr	until;
	uint	bits;
	uint	serial;
};

int cert_pem_create(const char *fn, uint pkey_bits, struct ffssl_cert_newinfo *ci)
{
	int r = 1;
	ffvec buf = {};
	ffstr kbuf = {}, cbuf = {};
	ffssl_key *k = NULL;
	ffssl_cert *c = NULL;

	if (ffssl_key_create(&k, pkey_bits, FFSSL_PKEY_RSA))
		goto end;
	if (ffssl_key_print(k, &kbuf))
		goto end;

	fftime t;
	fftime_now(&t);
	ci->pkey = k;
	if (ffssl_cert_create(&c, ci))
		goto end;
	if (ffssl_cert_print(c, &cbuf))
		goto end;

	ffvec_addstr(&buf, &cbuf);
	ffvec_addstr(&buf, &kbuf);
	if (fffile_writewhole(fn, buf.ptr, buf.len, 0)) {
		syserrlog("file write: %s", fn);
		goto end;
	}

	r = 0;

end:
	ffvec_free(&buf);
	ffstr_free(&kbuf);
	ffstr_free(&cbuf);
	return r;
}

#define R_DONE  100
#define R_BADVAL  101

static int cert_fin(void *obj)
{
	struct cert_conf *cc = obj;
	fftime now, since = {}, until = {};
	ffdatetime dt;

	if (!cc->bits)
		cc->bits = 2048;

	fftime_now(&now);

	if (!cc->from.len) {
		since = now;
	} else {
		if (cc->from.len != fftime_fromstr1(&dt, cc->from.ptr, cc->from.len, FFTIME_YMD)) {
			errlog("incorrect date value: %S", &cc->from);
			return R_DONE;
		}
		fftime_join1(&since, &dt);
		since.sec -= FFTIME_1970_SECONDS;
	}

	if (!cc->until.len) {
		until = now;
		until.sec += 24*60*60;
	} else {
		if (cc->until.len != fftime_fromstr1(&dt, cc->until.ptr, cc->until.len, FFTIME_YMD)) {
			errlog("incorrect date value: %S", &cc->until);
			return R_DONE;
		}
		fftime_join1(&until, &dt);
		until.sec -= FFTIME_1970_SECONDS;
	}

	if (!cc->serial) {
		ffrand_seed(now.sec);
		cc->serial = ffrand_get();
	}

	struct ffssl_cert_newinfo ci = {
		.subject = cc->subject,
		.serial = cc->serial,
		.from_time = since.sec,
		.until_time = until.sec,
	};

	if (!cc->output)
		cc->output = ffsz_dup("cert.pem");

	if (cert_pem_create(cc->output, cc->bits, &ci))
		return R_DONE;

	infolog("generated certificate & key: %s", cc->output);
	return R_DONE;
}

static int cert_help()
{
	exe->print(
"Generate certificate+key PEM file\n\
\n\
    `netmill cert generate` [OPTIONS]\n\
\n\
OPTIONS:\n\
\n\
Private key:\n\
  `bits` NUMBER       Key bits (default: 2048)\n\
\n\
Certificate:\n\
  `from` DATE         Valid from, e.g. \"2000-01-01 00:00:00\" (default: now)\n\
  `subject` STR       Subject\n\
  `until` DATE        Valid until (default: now + 1 day)\n\
  `serial` NUMBER     Serial number (default: random)\n\
\n\
Output:\n\
  `output` FILE       Output file name (default: cert.pem)\n\
");
	return R_DONE;
}

#define O(m)  (void*)(ffsize)FF_OFF(struct cert_conf, m)
static const struct ffarg cert_gen_args[] = {
	{ "bits",		'u',	O(bits) },
	{ "from",		'S',	O(from) },
	{ "output",		'=s',	O(output) },
	{ "serial",		'u',	O(serial) },
	{ "subject",	'S',	O(subject) },
	{ "until",		'S',	O(until) },
	{}
};
#undef O

static const struct ffarg cert_args[] = {
	{ "-help",			'1',	cert_help },
	{ "generate",		'>',	cert_gen_args },
	{ "\0\1",			'1',	cert_help },
	{}
};

static nml_op* cert_create(char **argv)
{
	struct cert_conf *cc = ffmem_new(struct cert_conf);

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, cert_args, cc, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
		{}
		else if (r == R_BADVAL)
			errlog("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			errlog("command line: %s\n", as.error);
		return NULL;
	}

	return cc;
}

static void cert_close(nml_op *op)
{
}

static void cert_run(nml_op *op)
{
	cert_fin(op);
}

static void cert_signal(nml_op *op, uint signal)
{
}

const struct nml_operation_if nml_op_cert = {
	cert_create,
	cert_close,
	cert_run,
	cert_signal,
};
