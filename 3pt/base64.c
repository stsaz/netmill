/** Base64 converter */

#include "base64.h"

typedef unsigned char u_char;

/* nginx/src/core/ngx_string.c, ngx_encode_base64_internal()
Copyright (C) Igor Sysoev
Copyright (C) Nginx, Inc. */
static size_t _base64_encode(char *dst, size_t cap, const void *src, size_t len, const u_char *basis, unsigned int padding)
{
	u_char *d = (u_char*)dst, *s = (u_char*)src;

	if (dst == NULL)
		return (len + 2) / 3 * 4;

	if (cap < (len + 2) / 3 * 4)
		return 0;

	while (len > 2) {
		*d++ = basis[(s[0] >> 2) & 0x3f];
		*d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
		*d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
		*d++ = basis[s[2] & 0x3f];

		s += 3;
		len -= 3;
	}

	if (len != 0) {
		*d++ = basis[(s[0] >> 2) & 0x3f];

		if (len == 1) {
			*d++ = basis[(s[0] & 3) << 4];
			if (padding) {
				*d++ = '=';
			}

		} else {
			*d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
			*d++ = basis[(s[1] & 0x0f) << 2];
		}

		if (padding) {
			*d++ = '=';
		}
	}

	return d - (u_char*)dst;
}

size_t base64_encode(char *dst, size_t cap, const void *src, size_t len)
{
	return _base64_encode(dst, cap, src, len,
		(u_char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 1);
}

size_t base64url_encode(char *dst, size_t cap, const void *src, size_t len)
{
	return _base64_encode(dst, cap, src, len,
		(u_char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 0);
}
