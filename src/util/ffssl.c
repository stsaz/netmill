/** OpenSSL wrapper
2015, Simon Zolin */

typedef unsigned int uint;
#include "ssl.h"
#include <ffsys/error.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_RECV_MIN  1500 // minimum buffer size for recv()

// Disable weak ciphers or those offering no encryption (eNULL) and no authentication (aNULL)
#define CIPHERS_DEFAULT  "!aNULL:!eNULL:!EXP:!MD5:HIGH"

struct ssl_global {
	int conn_idx
		, verify_cb_idx
		, bio_con_idx;
	BIO_METHOD *bio_meth;
};
static struct ssl_global *g;

struct ssl_rbuf {
	uint cap, off, len;
	char data[BUF_RECV_MIN];
};

struct ssl_iobuf {
	ssize_t len, processed;
	void *ptr;

	struct ssl_rbuf rbuf;
};

static inline void ssl_iobuf_reset(struct ssl_iobuf *iobuf) {
	iobuf->len = -1;
	iobuf->processed = -1;
	iobuf->ptr = NULL;
}

/* BIO method for asynchronous I/O */
static int async_bio_write(BIO *bio, const char *buf, int len);
static int async_bio_read(BIO *bio, char *buf, int len);
static long async_bio_ctrl(BIO *bio, int cmd, long num, void *ptr);
static int async_bio_create(BIO *bio);
static int async_bio_destroy(BIO *bio);


enum FFSSL_E {
	FFSSL_EOK = 0,
	FFSSL_ESYS,

	FFSSL_ECTXNEW,
	FFSSL_ECTX_CHECK_PKEY,
	FFSSL_ECTX_SET_CIPHER_LIST,
	FFSSL_ECTX_SET_CIPHERSUITES,
	FFSSL_EUSECERT,
	FFSSL_EUSEPKEY,
	FFSSL_ECTX_LOAD_VERIFY,
	FFSSL_ELOADCA,
	FFSSL_ESETTLSSRVNAME,

	FFSSL_ENEW,
	FFSSL_ENEWIDX,
	FFSSL_ECTX_SETDATA,
	FFSSL_ESETHOSTNAME,
	FFSSL_EBIONEW,

	/* For these codes SSL_get_error() value is stored in LSB#1:
		uint e = "00 00 SSL_get_error FFSSL_E" */
	FFSSL_EHANDSHAKE,
	FFSSL_EREAD,
	FFSSL_EWRITE,
	FFSSL_ESHUT,
};

static const char *const ffssl_funcstr[] = {
	"",
	"system",

	"SSL_CTX_new",
	"SSL_CTX_check_private_key",
	"SSL_CTX_set_cipher_list",
	"SSL_CTX_set_ciphersuites",
	"SSL_CTX_use_certificate",
	"SSL_CTX_use_PrivateKey",
	"SSL_CTX_load_verify*",
	"SSL_load_client_CA_file",
	"SSL_CTX_set_tlsext_servername*",

	"SSL_new",
	"SSL*_get_ex_new_index",
	"SSL*_set_ex_data",
	"SSL_set_tlsext_host_name",
	"BIO_new",

	"SSL_do_handshake",
	"SSL_read",
	"SSL_write",
	"SSL_shutdown",
};

const char* ffssl_error(int e, char *buf, size_t cap)
{
	ffstr s = { 0, buf };
	uint eio = ((uint)e >> 8);

	ffstr_addfmt(&s, cap, "%s: ", ffssl_funcstr[e & 0xff]);

	if (e == FFSSL_ESYS
		|| eio == SSL_ERROR_SYSCALL) {

		fferr_str(fferr_last(), s.ptr + s.len, cap - s.len);
		s.len = ffsz_len(s.ptr);
		goto done;

	} else if (eio != 0 && eio != SSL_ERROR_SSL) {
		ffstr_addfmt(&s, cap, "(0x%xu)", eio);
		goto done;
	}

	while (0 != (e = ERR_get_error())) {
		ffstr_addfmt(&s, cap, "(0x%xd) %s in %s:%s(). "
			, e, ERR_reason_error_string(e), ERR_lib_error_string(e), ERR_func_error_string(e));
	}

done:
	ffstr_addchar(&s, cap, '\0');
	return s.ptr;
}

int ffssl_init()
{
	SSL_library_init();
	SSL_load_error_strings();
	if (NULL == (g = ffmem_new(struct ssl_global)))
		return FFSSL_ESYS;
	if (-1 == (g->conn_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL)))
		return FFSSL_ENEWIDX;
	if (-1 == (g->verify_cb_idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL)))
		return FFSSL_ENEWIDX;
	if (-1 == (g->bio_con_idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL)))
		return FFSSL_ENEWIDX;

	BIO_METHOD *bm;
	if (NULL == (bm = BIO_meth_new(BIO_TYPE_MEM, "aio")))
		return FFSSL_ESYS;
	BIO_meth_set_write(bm, async_bio_write);
	BIO_meth_set_read(bm, async_bio_read);
	BIO_meth_set_ctrl(bm, async_bio_ctrl);
	BIO_meth_set_create(bm, async_bio_create);
	BIO_meth_set_destroy(bm, async_bio_destroy);
	g->bio_meth = bm;

	return 0;
}

void ffssl_uninit()
{
	if (!g) return;

	ERR_free_strings();
	BIO_meth_free(g->bio_meth);
	ffmem_free(g);  g = NULL;
}


int ffssl_ctx_create(SSL_CTX **pctx)
{
	SSL_CTX *ctx;
	if (NULL == (ctx = SSL_CTX_new(SSLv23_method())))
		return FFSSL_ECTXNEW;
	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	*pctx = ctx;
	return 0;
}

void ffssl_ctx_free(SSL_CTX *ctx) { SSL_CTX_free(ctx); }

static void _ffssl_ctx_proto_allow(SSL_CTX *ctx, uint protos)
{
	if (protos == 0)
		protos = FFSSL_PROTO_TLS1 | FFSSL_PROTO_TLS11 | FFSSL_PROTO_TLS12 | FFSSL_PROTO_TLS13;

	uint op = SSL_OP_NO_SSLv3;
	static const uint no_protos[] = {
		SSL_OP_NO_TLSv1, SSL_OP_NO_TLSv1_1, SSL_OP_NO_TLSv1_2
	};
	for (uint i = 0;  i != FF_COUNT(no_protos);  i++) {
		if (!(protos & (1 << i)))
			op |= no_protos[i];
	}

	SSL_CTX_set_options(ctx, op);
}

/** Set certificate on a context */
static int _ffssl_ctx_cert(SSL_CTX *ctx, const struct ffssl_ctx_conf *o)
{
	if (o->cert_file != NULL
		&& 1 != SSL_CTX_use_certificate_chain_file(ctx, o->cert_file))
		return FFSSL_EUSECERT;

	if (o->cert_data.len != 0) {
		X509 *cert;
		if (NULL == (cert = ffssl_cert_read(o->cert_data, 0)))
			return FFSSL_EUSECERT;
		int r = SSL_CTX_use_certificate(ctx, cert);
		X509_free(cert);
		if (r != 1)
			return FFSSL_EUSECERT;
	}

	if (o->cert != NULL
		&& 1 != SSL_CTX_use_certificate(ctx, o->cert))
		return FFSSL_EUSECERT;

	return 0;
}

/** Set private key on a context */
static int _ffssl_ctx_pkey(SSL_CTX *ctx, const struct ffssl_ctx_conf *o)
{
	if (o->pkey_file != NULL
		&& 1 != SSL_CTX_use_PrivateKey_file(ctx, o->pkey_file, SSL_FILETYPE_PEM))
		return FFSSL_EUSEPKEY;

	if (o->pkey_data.len != 0) {
		EVP_PKEY *pk;
		if (NULL == (pk = ffssl_key_read(o->pkey_data, 0)))
			return FFSSL_EUSEPKEY;
		int r = SSL_CTX_use_PrivateKey(ctx, pk);
		EVP_PKEY_free(pk);
		if (r != 1)
			return FFSSL_EUSEPKEY;
	}

	if (o->pkey != NULL
		&& 1 != SSL_CTX_use_PrivateKey(ctx, o->pkey))
		return FFSSL_EUSEPKEY;

	return 0;
}

static int _ffssl_tls_srvname(SSL *ssl, int *ad, void *arg)
{
	void *udata = SSL_get_ex_data(ssl, g->conn_idx);
	ffssl_tls_srvname_cb srvname = arg;
	return srvname(ssl, ad, arg, udata);
}

static int _ffssl_ctx_tls_srvname_set(SSL_CTX *ctx, ffssl_tls_srvname_cb func)
{
	if (!SSL_CTX_set_tlsext_servername_callback(ctx, &_ffssl_tls_srvname))
		return FFSSL_ESETTLSSRVNAME;
	if (!SSL_CTX_set_tlsext_servername_arg(ctx, func))
		return FFSSL_ESETTLSSRVNAME;
	return 0;
}

static int _ffssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509ctx)
{
	SSL *ssl = X509_STORE_CTX_get_ex_data(x509ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	void *udata = SSL_get_ex_data(ssl, g->conn_idx);
	ffssl_verify_cb verify = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), g->verify_cb_idx);
	if (verify != NULL)
		return verify(preverify_ok, x509ctx, udata);
	return preverify_ok;
}

int ffssl_ctx_conf(SSL_CTX *ctx, const struct ffssl_ctx_conf *o)
{
	int r;

	if ((r = _ffssl_ctx_cert(ctx, o)))
		return r;

	if ((r = _ffssl_ctx_pkey(ctx, o)))
		return r;

	if (!SSL_CTX_check_private_key(ctx))
		return FFSSL_ECTX_CHECK_PKEY;

	if (1 != SSL_CTX_set_cipher_list(ctx, (o->ciphers != NULL && o->ciphers[0] != '\0') ? o->ciphers : CIPHERS_DEFAULT))
		return FFSSL_ECTX_SET_CIPHER_LIST;

	if (o->ciphers_tls13 != NULL
		&& o->ciphers_tls13[0] != '\0'
		&& 1 != SSL_CTX_set_ciphersuites(ctx, o->ciphers_tls13))
		return FFSSL_ECTX_SET_CIPHERSUITES;

	if (o->use_server_cipher)
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

	if (o->tls_srvname_func != NULL
		&& 0 != (r = _ffssl_ctx_tls_srvname_set(ctx, o->tls_srvname_func)))
		return r;

	_ffssl_ctx_proto_allow(ctx, o->allowed_protocols);

	if (o->verify_func != NULL) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, _ffssl_verify_cb);
		if (!SSL_CTX_set_ex_data(ctx, g->verify_cb_idx, o->verify_func))
			return FFSSL_ECTX_SETDATA;
	}

	if (o->verify_depth != 0 && o->verify_depth != ~0U)
		SSL_CTX_set_verify_depth(ctx, o->verify_depth);

	if (o->CA_file != NULL && !SSL_CTX_load_verify_file(ctx, o->CA_file))
		return FFSSL_ECTX_LOAD_VERIFY;

	if (o->CA_path != NULL && !SSL_CTX_load_verify_dir(ctx, o->CA_path))
		return FFSSL_ECTX_LOAD_VERIFY;

	if (o->verify_depth != 0 && o->CA_file == NULL && o->CA_path == NULL
		&& !SSL_CTX_set_default_verify_paths(ctx))
		return FFSSL_ECTX_LOAD_VERIFY;

	if (o->client_CA_file != NULL) {
		STACK_OF(X509_NAME) *names;
		if (NULL == (names = SSL_load_client_CA_file(o->client_CA_file)))
			return FFSSL_ELOADCA;
		SSL_CTX_set_client_CA_list(ctx, names);
	}

	return 0;
}


int ffssl_ctx_cache(SSL_CTX *ctx, int size)
{
	if (size == -1) {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
		return 0;
	}

	int sessid_ctx = 0;
	SSL_CTX_set_session_id_context(ctx, (void*)&sessid_ctx, sizeof(int));
	if (size != 0)
		SSL_CTX_sess_set_cache_size(ctx, size);
	return 0;
}

void ffssl_ctx_sess_del(SSL_CTX *ctx, SSL *c)
{
	SSL_CTX_remove_session(ctx, SSL_get_session(c));
}


int ffssl_conn_create(SSL **con, SSL_CTX *ctx, uint flags, struct ffssl_opt *opt)
{
	SSL *c;
	int e;
	BIO *bio;

	if (NULL == (c = SSL_new(ctx)))
		return FFSSL_ENEW;

	if (opt->udata != NULL
		&& 0 == SSL_set_ex_data(c, g->conn_idx, opt->udata)) {
		e = FFSSL_ECTX_SETDATA;
		goto fail;
	}

	if (flags & FFSSL_ACCEPT) {
		SSL_set_accept_state(c);

	} else {
		SSL_set_connect_state(c);

		if (opt->tls_hostname != NULL
			&& 1 != SSL_set_tlsext_host_name(c, opt->tls_hostname)) {
			e = FFSSL_ESETHOSTNAME;
			goto fail;
		}
	}

	if (flags & FFSSL_IOBUF) {
		struct ssl_iobuf *iobuf;
		if (NULL == (iobuf = ffmem_alloc(sizeof(struct ssl_iobuf)))) {
			e = FFSSL_ESYS;
			goto fail;
		}
		iobuf->rbuf.cap = BUF_RECV_MIN;
		iobuf->rbuf.len = iobuf->rbuf.off = 0;
		ssl_iobuf_reset(iobuf);

		if (NULL == (bio = BIO_new(g->bio_meth))) {
			ffmem_free(iobuf);
			e = FFSSL_EBIONEW;
			goto fail;
		}
		BIO_set_data(bio, iobuf);
		BIO_set_ex_data(bio, g->bio_con_idx, iobuf);
		SSL_set_bio(c, bio, bio);
	}

	*con = c;
	return 0;

fail:
	ffssl_conn_free(c);
	return e;
}

void ffssl_conn_free(SSL *c) { SSL_free(c); }

void ffssl_conn_setctx(SSL *c, SSL_CTX *ctx)
{
	SSL_set_SSL_CTX(c, ctx);
	SSL_set_options(c, SSL_CTX_get_options(ctx));
}

size_t ffssl_conn_get(SSL *c, uint flags)
{
	size_t r = 0;
	switch (flags) {
	case FFSSL_SESS_REUSED:
		r = SSL_session_reused(c);  break;

	case FFSSL_NUM_RENEGOTIATIONS:
		r = SSL_num_renegotiations(c);  break;

	case FFSSL_CERT_VERIFY_RESULT:
		r = SSL_get_verify_result(c);  break;
	}
	return r;
}

void* ffssl_conn_getptr(SSL *c, uint flags)
{
	void *r = NULL;
	switch (flags) {
	case FFSSL_HOSTNAME:
		r = (void*)SSL_get_servername(c, TLSEXT_NAMETYPE_host_name);  break;

	case FFSSL_CIPHER_NAME:
		r = (void*)SSL_get_cipher_name(c);  break;

	case FFSSL_VERSION:
		r = (void*)SSL_get_version(c);  break;

	case FFSSL_PEER_CERT:
		r = SSL_get_peer_certificate(c);  break;
	}
	return r;
}


int ffssl_conn_handshake(SSL *c)
{
	int r = SSL_do_handshake(c);
	if (r != 1) {
		r = SSL_get_error(c, r);
		if (r == SSL_ERROR_WANT_READ
			|| r == SSL_ERROR_WANT_WRITE)
			return r;
		return FFSSL_EHANDSHAKE | (r << 8);
	}
	return 0;
}

int ffssl_conn_read(SSL *c, void *buf, size_t size)
{
	int r = SSL_read(c, buf, ffmin(size, 0xffffffff));
	if (r < 0) {
		r = SSL_get_error(c, r);
		if (!(r == SSL_ERROR_WANT_READ
			|| r == SSL_ERROR_WANT_WRITE))
			r = FFSSL_EREAD | (r << 8);
		return -r;
	}
	return r;
}

int ffssl_conn_write(SSL *c, const void *buf, size_t size)
{
	int r = SSL_write(c, buf, ffmin(size, 0xffffffff));
	if (r < 0) {
		r = SSL_get_error(c, r);
		if (!(r == SSL_ERROR_WANT_READ
			|| r == SSL_ERROR_WANT_WRITE))
			r = FFSSL_EWRITE | (r << 8);
		return -r;
	}
	return r;
}

int ffssl_conn_shut(SSL *c)
{
	int r = SSL_shutdown(c); //send 'close-notify' alert
	if (!(r == 1 || r == 0)) {
		r = SSL_get_error(c, r);
		if (r == SSL_ERROR_WANT_READ
			|| r == SSL_ERROR_WANT_WRITE)
			return r;

		if (!ERR_peek_error())
			return 0;

		return FFSSL_ESHUT | (r << 8);
	}
	return 0;
}

/*
Server-side handshake:

1.
ffssl_conn_handshake() ->              libssl ->          BIO
                       <-(want-read)--        <-(retry)--

2.
ffstr buf = ffssl_conn_iobuf(...)
r = recv(..., buf)
ffssl_conn_input(..., r)

3.
ffssl_conn_handshake() ->              libssl ->          BIO
                                              <-(data)--
                                              ->
                       <-(want-write)--        <-(retry)--

4.
ffstr data = ffssl_conn_iobuf(...)
r = send(..., data)
ffssl_conn_input(..., r)

5.
ffssl_conn_handshake() ->              libssl ->          BIO
                       <-(ok)--               <-(ok)--
*/

void ffssl_conn_iobuf(SSL *c, ffstr *data)
{
	BIO *bio = SSL_get_rbio(c);
	struct ssl_iobuf *iobuf = BIO_get_ex_data(bio, g->bio_con_idx);
	ffstr_set(data, iobuf->ptr, iobuf->len);
}

void ffssl_conn_input(SSL *c, size_t len)
{
	BIO *bio = SSL_get_rbio(c);
	struct ssl_iobuf *iobuf = BIO_get_ex_data(bio, g->bio_con_idx);
	iobuf->processed = len;
}

static int async_bio_read(BIO *bio, char *buf, int len)
{
	ssize_t r;
	struct ssl_iobuf *iobuf = BIO_get_data(bio);
	struct ssl_rbuf *rbuf = &iobuf->rbuf;

	if (iobuf->processed != -1) {
		// user filled OpenSSL/our buffer with data
		BIO_clear_retry_flags(bio);
		if (iobuf->ptr != rbuf->data) {
			// OpenSSL is the buffer's owner
			FF_ASSERT(buf == iobuf->ptr && len >= iobuf->processed);
			r = iobuf->processed;
			ssl_iobuf_reset(iobuf);
			return (int)r;
		}

		// we own the buffer
		rbuf->len = iobuf->processed;
		ssl_iobuf_reset(iobuf);
		if (rbuf->len == 0)
			return 0;
	}

	if (rbuf->len != 0) {
		// return to OpenSSL some data from our buffer
		r = _ffs_copy(buf, len, rbuf->data + rbuf->off, rbuf->len);
		rbuf->len -= r;
		rbuf->off += r;
		if (rbuf->len == 0)
			rbuf->off = 0;
		return (int)r;
	}

	// let the user write directly to OpenSSL's buffer
	iobuf->ptr = buf;
	iobuf->len = len;
	if ((uint)len < rbuf->cap) {
		// OpenSSL needs very little data, we want to use a bigger buffer
		iobuf->ptr = rbuf->data;
		iobuf->len = rbuf->cap;
	}

	BIO_set_retry_read(bio);
	return -1;
}

static int async_bio_write(BIO *bio, const char *buf, int len)
{
	ssize_t r;
	struct ssl_iobuf *iobuf = BIO_get_data(bio);

	if (iobuf->processed != -1) {
		// user consumed some data from OpenSSL's buffer
		FF_ASSERT(buf == iobuf->ptr && len >= iobuf->processed);
		BIO_clear_retry_flags(bio);
		r = iobuf->processed;
		ssl_iobuf_reset(iobuf);
		return (int)r;
	}

	// let the user read directly from OpenSSL's buffer
	iobuf->ptr = (void*)buf;
	iobuf->len = len;
	BIO_set_retry_write(bio);
	return -1;
}

static long async_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	switch (cmd) {
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		return 1;
	}

	return 0;
}

static int async_bio_create(BIO *bio)
{
	BIO_set_init(bio, 1);
	return 1;
}

static int async_bio_destroy(BIO *bio)
{
	struct ssl_iobuf *iobuf = BIO_get_data(bio);
	ffmem_free(iobuf);
	return 1;
}


static ffuint64 time_from_ASN1time(const ASN1_TIME *src)
{
	time_t t = 0;
	ASN1_TIME *at = ASN1_TIME_new();
	X509_time_adj_ex(at, 0, 0, &t);
	int days = 0, secs = 0;
	ASN1_TIME_diff(&days, &secs, at, src);
	ASN1_TIME_free(at);
	return (ffint64)days * 24*60*60 + secs;
}

void ffssl_cert_info(X509 *cert, struct ffssl_cert_info *info)
{
	X509_NAME_oneline(X509_get_subject_name(cert), info->subject, sizeof(info->subject));
	X509_NAME_oneline(X509_get_issuer_name(cert), info->issuer, sizeof(info->issuer));
	info->valid_from = time_from_ASN1time(X509_get_notBefore(cert));
	info->valid_until = time_from_ASN1time(X509_get_notAfter(cert));
}

X509* ffssl_cert_read(ffstr data, uint flags)
{
	BIO *b;
	X509 *x;

	if (NULL == (b = BIO_new_mem_buf(data.ptr, data.len)))
		return NULL;

	x = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO_free_all(b);
	return x;
}

EVP_PKEY* ffssl_key_read(ffstr data, uint flags)
{
	BIO *b;
	if (NULL == (b = BIO_new_mem_buf(data.ptr, data.len)))
		return NULL;

	EVP_PKEY *key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

	BIO_free_all(b);
	return key;
}

int ffssl_key_create(EVP_PKEY **key, uint bits, uint flags)
{
	int r = -1;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;

	switch (flags & 0xff) {
	case FFSSL_PKEY_RSA:
		if (NULL == (rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL)))
			goto end;
		if (NULL == (pk = EVP_PKEY_new()))
			goto end;
		if (!EVP_PKEY_set1_RSA(pk, rsa))
			goto end;
		*key = pk;
		break;

	default:
		goto end;
	}

	r = 0;

end:
	if (r != 0) {
		EVP_PKEY_free(pk);
		RSA_free(rsa);
	}
	return r;
}

void ffssl_key_free(EVP_PKEY *key) { EVP_PKEY_free(key); }

/** Fill X509_NAME object. */
static int _ffssl_x509_name(X509_NAME *name, const ffstr *subject)
{
	int r;
	ffstr subj = *subject, pair, k, v;
	char buf[1024];

	if (subj.len != 0 && subj.ptr[0] == '/')
		ffstr_shift(&subj, 1);

	while (subj.len != 0) {
		ffstr_splitby(&subj, '/', &pair, &subj);

		if (ffstr_splitby(&pair, '=', &k, &v) < 0
			|| k.len == 0)
			goto end; // must be K=[V] pair

		if (sizeof(buf) == ffsz_copyn(buf, sizeof(buf), k.ptr, k.len))
			goto end; // too large key
		r = X509_NAME_add_entry_by_txt(name, buf, MBSTRING_ASC, (ffbyte*)v.ptr, v.len, -1, 0);
		if (r == 0)
			goto end;
	}

	return 0;

end:
	return -1;
}

int ffssl_cert_create(X509 **px509, struct ffssl_cert_newinfo *info)
{
	int r = -1;
	X509 *x509 = NULL;

	if (NULL == (x509 = X509_new()))
		goto end;

	if (!X509_set_version(x509, 2))
		goto end;
	ASN1_INTEGER_set(X509_get_serialNumber(x509), info->serial);
	if (!X509_set_pubkey(x509, info->pkey))
		goto end;

	time_t t = info->from_time;
	if (NULL == X509_time_adj_ex(X509_get_notBefore(x509), 0, 0, &t))
		goto end;

	t = info->until_time;
	if (NULL == X509_time_adj_ex(X509_get_notAfter(x509), 0, 0, &t))
		goto end;

	X509_NAME *name = X509_get_subject_name(x509);
	if (_ffssl_x509_name(name, &info->subject))
		goto end;

	X509_NAME *iss_name = name;
	EVP_PKEY *iss_pk = info->pkey;
	if (info->issuer_name != NULL) {
		iss_name = info->issuer_name;
		iss_pk = info->issuer_pkey;
	}
	if (!X509_set_issuer_name(x509, iss_name))
		goto end;
	if (!X509_sign(x509, iss_pk, EVP_sha1()))
		goto end;
	*px509 = x509;
	r = 0;

end:
	if (r != 0)
		X509_free(x509);
	return r;
}

void ffssl_cert_free(X509 *x509) { X509_free(x509); }

int ffssl_key_print(EVP_PKEY *key, ffstr *data)
{
	int r = -1;
	BIO *bio;
	BUF_MEM *bm;
	if (NULL == (bio = BIO_new(BIO_s_mem())))
		goto end;
	RSA *rsa = EVP_PKEY_get1_RSA(key);
	if (rsa == NULL)
		goto end;
	if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL))
		goto end;
	if (!BIO_get_mem_ptr(bio, &bm))
		goto end;
	if (NULL == ffstr_dup(data, bm->data, bm->length))
		goto end;
	r = 0;

end:
	BIO_free_all(bio);
	return r;
}

int ffssl_cert_print(X509 *x509, ffstr *data)
{
	int r = -1;
	BIO *bio;
	BUF_MEM *bm;
	if (NULL == (bio = BIO_new(BIO_s_mem())))
		goto end;
	if (!PEM_write_bio_X509(bio, x509))
		goto end;
	if (!BIO_get_mem_ptr(bio, &bm))
		goto end;
	if (NULL == ffstr_dup(data, bm->data, bm->length))
		goto end;
	r = 0;

end:
	BIO_free_all(bio);
	return r;
}
