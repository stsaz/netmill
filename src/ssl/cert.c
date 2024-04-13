/** netmill: ssl: generate certificate file
2023, Simon Zolin */

#include <netmill.h>
#include <util/ssl.h>
#include <ffsys/random.h>
#include <ffbase/args.h>

extern const nml_exe *exe;

#define CT_SYSERR(...) \
	exe->log(NULL, NML_LOG_SYSERR, "cert", NULL, __VA_ARGS__)

#define CT_ERR(...) \
	exe->log(NULL, NML_LOG_ERR, "cert", NULL, __VA_ARGS__)

#define CT_INFO(...) \
	exe->log(NULL, NML_LOG_INFO, "cert", NULL, __VA_ARGS__)

struct cert_exe {
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
		CT_SYSERR("file write: %s", fn);
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

static int cert_generate(struct cert_exe *cx)
{
	fftime now, since = {}, until = {};
	ffdatetime dt;

	if (!cx->bits)
		cx->bits = 2048;

	fftime_now(&now);

	if (!cx->from.len) {
		since = now;
	} else {
		if (cx->from.len != fftime_fromstr1(&dt, cx->from.ptr, cx->from.len, FFTIME_YMD)) {
			CT_ERR("incorrect date value: %S", &cx->from);
			return R_DONE;
		}
		fftime_join1(&since, &dt);
		since.sec -= FFTIME_1970_SECONDS;
	}

	if (!cx->until.len) {
		until = now;
		until.sec += 24*60*60;
	} else {
		if (cx->until.len != fftime_fromstr1(&dt, cx->until.ptr, cx->until.len, FFTIME_YMD)) {
			CT_ERR("incorrect date value: %S", &cx->until);
			return R_DONE;
		}
		fftime_join1(&until, &dt);
		until.sec -= FFTIME_1970_SECONDS;
	}

	if (!cx->serial) {
		ffrand_seed(now.sec);
		cx->serial = ffrand_get();
	}

	struct ffssl_cert_newinfo ci = {
		.subject = cx->subject,
		.serial = cx->serial,
		.from_time = since.sec,
		.until_time = until.sec,
	};

	if (!cx->output)
		cx->output = ffsz_dup("cert.pem");

	if (cert_pem_create(cx->output, cx->bits, &ci))
		return R_DONE;

	CT_INFO("generated certificate & key: %s", cx->output);
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

#define O(m)  (void*)(size_t)FF_OFF(struct cert_exe, m)
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
	struct cert_exe *cx = ffmem_new(struct cert_exe);

	uint n = 0;
	while (argv[n]) {
		n++;
	}

	struct ffargs as = {};
	int r = ffargs_process_argv(&as, cert_args, cx, FFARGS_O_PARTIAL | FFARGS_O_DUPLICATES, argv, n);
	if (r) {
		if (r == R_DONE)
			exe->exit(0);
		else if (r == R_BADVAL)
			CT_ERR("command line: near '%s': bad value\n", as.argv[as.argi-1]);
		else
			CT_ERR("command line: %s\n", as.error);
		return NULL;
	}

	return cx;
}

static void cert_close(nml_op *op)
{
	struct cert_exe *cx = op;
	ffmem_free(cx);
}

static void cert_run(nml_op *op)
{
	cert_generate(op);
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
