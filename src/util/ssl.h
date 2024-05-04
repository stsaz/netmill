/** OpenSSL wrapper
2015, Simon Zolin */

/*
ffssl_init ffssl_uninit
ffssl_error
Context:
	ffssl_ctx_create ffssl_ctx_free
	ffssl_ctx_conf
	ffssl_ctx_ca
	ffssl_ctx_cache
	ffssl_ctx_sess_del
Connection:
	ffssl_conn_create ffssl_conn_free
	ffssl_conn_get ffssl_conn_getptr
	ffssl_conn_handshake
	ffssl_conn_read ffssl_conn_write
	ffssl_conn_shut
	ffssl_conn_iobuf
	ffssl_conn_input
	ffssl_conn_setctx
Keys:
	ffssl_key_create ffssl_key_free
	ffssl_key_read
	ffssl_key_print
Certificates:
	ffssl_cert_info
	ffssl_cert_verify_errstr
	ffssl_cert_create ffssl_cert_free
	ffssl_cert_read
	ffssl_cert_print
*/

#pragma once
#include <ffsys/error.h>
#include <ffbase/string.h>

/** Get last error message */
FF_EXTERN const char* ffssl_error(int e, char *buf, size_t cap);


FF_EXTERN int ffssl_init();

FF_EXTERN void ffssl_uninit();


typedef struct evp_pkey_st ffssl_key;
typedef struct x509_st ffssl_cert;
typedef struct ssl_ctx_st ffssl_ctx;
typedef struct ssl_st ffssl_conn;

FF_EXTERN int ffssl_ctx_create(ffssl_ctx **ctx);

FF_EXTERN void ffssl_ctx_free(ffssl_ctx *ctx);

enum FFSSL_SRVNAME {
	FFSSL_SRVNAME_OK = 0, // SSL_TLSEXT_ERR_OK
	FFSSL_SRVNAME_NOACK = 3, // SSL_TLSEXT_ERR_NOACK
};

/** Return enum FFSSL_SRVNAME */
typedef int (*ffssl_tls_srvname_cb)(ffssl_conn *ssl, int *ad, void *arg, void *udata);

enum FFSSL_PROTO {
	FFSSL_PROTO_DEFAULT = 0, // all TLS
	FFSSL_PROTO_TLS1 = 1,
	FFSSL_PROTO_TLS11 = 2,
	FFSSL_PROTO_TLS12 = 4,
	FFSSL_PROTO_TLS13 = 8,
};

struct x509_store_ctx_st; // X509_STORE_CTX
typedef int (*ffssl_verify_cb)(int preverify_ok, struct x509_store_ctx_st *x509ctx, void *udata);

struct ffssl_ctx_conf {
	char *cert_file;
	ffstr cert_data;
	ffssl_cert *cert;

	char *pkey_file; // PEM file name containing private key
	ffstr pkey_data;
	ffssl_key *pkey;

	ffssl_verify_cb	verify_func;
	uint			verify_depth; // -1: default
	const char		*CA_file, *CA_path; // NULL: load default CA
	const char		*client_CA_file;

	char *ciphers; // ciphers separated by ':'
	char *ciphers_tls13; // TLSv1.3 ciphersuites separated by ':'
	uint use_server_cipher :1;

	ffssl_tls_srvname_cb tls_srvname_func;

	uint allowed_protocols; // enum FFSSL_PROTO
};

/** Configurate ffssl_conn context. */
FF_EXTERN int ffssl_ctx_conf(ffssl_ctx *ctx, const struct ffssl_ctx_conf *conf);

/**
size:
	0:  default;
	-1: disabled;
	>0: cache size. */
FF_EXTERN int ffssl_ctx_cache(ffssl_ctx *ctx, int size);

FF_EXTERN void ffssl_ctx_sess_del(ffssl_ctx *ctx, ffssl_conn *c);


enum FFSSL_CONN_CREATE {
	/** Connection type: client (default) or server. */
	FFSSL_CONNECT = 0,
	FFSSL_ACCEPT = 1,

	/** Don't perform any I/O operations within the library itself.
	The caller must handle FFSSL_WANTREAD and FFSSL_WANTWRITE error codes:
	 use ffssl_conn_iobuf() to get ffssl_conn buffer for the data that needs to be read/sent.
	After I/O is performed, ffssl_conn_input() must be called to set the number of bytes transferred. */
	FFSSL_IOBUF = 2,
};

struct ffssl_opt {
	void *udata; // opaque data for callback functions
	const char *tls_hostname; // set hostname for SNI
};

/** Create a connection.
flags: enum FFSSL_CONN_CREATE
opt: additional options.
Return enum FFSSL_E. */
FF_EXTERN int ffssl_conn_create(ffssl_conn **c, ffssl_ctx *ctx, uint flags, struct ffssl_opt *opt);

FF_EXTERN void ffssl_conn_free(ffssl_conn *c);

FF_EXTERN void ffssl_conn_setctx(ffssl_conn *c, ffssl_ctx *ctx);

enum FFSSL_INFO {
	FFSSL_SESS_REUSED,
	FFSSL_NUM_RENEGOTIATIONS,
	FFSSL_CERT_VERIFY_RESULT, //X509_V_OK or other X509_V_*
};

/**
flags: enum FFSSL_INFO */
FF_EXTERN size_t ffssl_conn_get(ffssl_conn *c, uint flags);

enum FFSSL_INFO_PTR {
	FFSSL_HOSTNAME,
	FFSSL_CIPHER_NAME,
	FFSSL_VERSION,
	FFSSL_PEER_CERT, // Get peer certificate.  Must free with ffssl_cert_free().
};

/**
flags: enum FFSSL_INFO_PTR */
FF_EXTERN void* ffssl_conn_getptr(ffssl_conn *c, uint flags);

/**
These codes must be handled by user.
Call ffssl_error() for any other code. */
enum FFSSL_EIO {
	FFSSL_WANTREAD = 2, // SSL_ERROR_WANT_READ
	FFSSL_WANTWRITE = 3, // SSL_ERROR_WANT_WRITE
};

/**
Return 0 on success;
	enum FFSSL_EIO for more I/O;
	enum FFSSL_E on error. */
FF_EXTERN int ffssl_conn_handshake(ffssl_conn *c);

/**
Return the number of bytes read;
	<0: enum FFSSL_EIO (negative value);
	<0: enum FFSSL_E on error. */
FF_EXTERN int ffssl_conn_read(ffssl_conn *c, void *buf, size_t size);

/**
Return the number of bytes sent;
	<0: enum FFSSL_EIO (negative value);
	<0: enum FFSSL_E on error. */
FF_EXTERN int ffssl_conn_write(ffssl_conn *c, const void *buf, size_t size);

/**
Return 0 on success;
	enum FFSSL_EIO for more I/O;
	enum FFSSL_E on error. */
FF_EXTERN int ffssl_conn_shut(ffssl_conn *c);

/** Get buffer for I/O.
data:
	FFSSL_WANTREAD: buffer for encrypted data to be read from socket
	FFSSL_WANTWRITE: encrypted data to be written to socket */
FF_EXTERN void ffssl_conn_iobuf(ffssl_conn *c, ffstr *data);

/** Set the number of encrypted bytes read/written. */
FF_EXTERN void ffssl_conn_input(ffssl_conn *c, size_t len);


enum FFSSL_PKEY {
	FFSSL_PKEY_RSA,
};

/** Create a private key.
flags: enum FFSSL_PKEY */
FF_EXTERN int ffssl_key_create(ffssl_key **key, uint bits, uint flags);

FF_EXTERN void ffssl_key_free(ffssl_key *key);

/** Get private key from PEM data.
Return NULL on error. */
FF_EXTERN ffssl_key* ffssl_key_read(ffstr data, uint flags);

/** Convert private key to text */
FF_EXTERN int ffssl_key_print(ffssl_key *key, ffstr *data);


struct ffssl_cert_info {
	char subject[1024];
	char issuer[1024];
	ffuint64 valid_from;
	ffuint64 valid_until;
};

/** Get certificate info */
FF_EXTERN void ffssl_cert_info(ffssl_cert *cert, struct ffssl_cert_info *info);

#define ffssl_cert_verify_errstr(e)  X509_verify_cert_error_string(e)

struct ffssl_cert_newinfo {
	ffstr subject; // "/K1=[V1]"...
	int serial;
	ffuint64 from_time; // UNIX timestamp
	ffuint64 until_time;

	ffssl_key *pkey;

	void *issuer_name; // X509_NAME*. NULL for self-signed
	ffssl_key *issuer_pkey;
};

/** Create a certificate. */
FF_EXTERN int ffssl_cert_create(ffssl_cert **cert, struct ffssl_cert_newinfo *info);

FF_EXTERN void ffssl_cert_free(ffssl_cert *cert);

/** Get certificate from PEM data.
Return NULL on error. */
FF_EXTERN ffssl_cert* ffssl_cert_read(ffstr data, uint flags);

/** Convert certificate to text */
FF_EXTERN int ffssl_cert_print(ffssl_cert *cert, ffstr *data);
