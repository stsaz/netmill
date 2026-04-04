/** SOCKS5
2026, Simon Zolin */

/*
socks5_cl_auth_find
socks5_cl_auth2_write socks5_cl_auth2_read
socks5_connect_write socks5_connect_read
*/

/*
cl_auth    >>
           << sv_auth
[cl_auth2  >>
           << sv_auth2]
cl_connect >>
           << sv_connect
data      <<->> data
*/

#pragma once
#define SOCKS5_TCP_PORT  1080

enum SOCKS5_AUTH {
	SOCKS5_AUTH_NONE,
	SOCKS5_AUTH_USERPW = 2,
	SOCKS5_AUTH_NOMATCH = 0xff,
};

struct socks5_cl_auth {
	u_char ver; // 5

	u_char nauth;
	u_char auth[0]; // enum SOCKS5_AUTH
};

/** Check if the client supports the specified auth method.
Return N of bytes read;
 0: need more data;
 <0: error;
 0xffff: no match */
static inline int socks5_cl_auth_find(const char *d, size_t len, uint method)
{
	if (2 > len)
		return 0;
	if (d[0] != 5
		|| d[1] == 0)
		return -1;

	uint n = 2 + d[1];
	if (n < len)
		return 0;

	for (uint i = 2;  i < n;  i++) {
		if (method == (u_char)d[i])
			return n;
	}
	return 0xffff;
}

struct socks5_sv_auth {
	u_char ver;
	u_char cauth; // enum SOCKS5_AUTH
};


struct socks5_cl_auth2 {
	u_char ver; // 1

	u_char idlen;
	u_char id[0];

	// u_char pwlen;
	// u_char pw[0];
};

static inline int socks5_cl_auth2_write(char *dst, size_t cap, ffstr user, ffstr password)
{
	FF_ASSERT(user.len <= 255);
	FF_ASSERT(password.len <= 255);
	uint n = 3 + user.len + password.len;
	if (n > cap)
		return 0;

	*dst++ = 1;
	*dst++ = user.len;
	dst = ffmem_copy(dst, user.ptr, user.len);
	*dst++ = password.len;
	dst = ffmem_copy(dst, password.ptr, password.len);
	return n;
}

static inline int socks5_cl_auth2_read(const char *data, size_t len, ffstr *user, ffstr *password)
{
	const char *p = data, *end = data + len;
	if (3 > len)
		return 0;
	if (*p++ != 1)
		return -1; // 'subversion'

	uint n = *p++;
	if (p + n + 1 > end)
		return 0;
	user->ptr = (char*)p;
	user->len = n;
	p += n;

	n = *p++;
	if (p + n > end)
		return 0;
	password->ptr = (char*)p;
	password->len = n;
	p += n;

	return p - data;
}

struct socks5_sv_auth2 {
	u_char ver; // 1
	u_char status; // 0: ok
};


enum SOCKS5_ADDR {
	SOCKS5_ADDR_IPV4 = 1,
	SOCKS5_ADDR_HOST = 3,
	SOCKS5_ADDR_IPV6 = 4,
};

enum SOCKS5_CMD {
	SOCKS5_CMD_STREAM = 1,
	SOCKS5_CMD_TCP_PORT = 2,
	SOCKS5_CMD_UDP_PORT = 3,
};

struct socks5_connect {
	u_char ver; // 5
	u_char cmd_status; // cmd: enum SOCKS5_CMD
	u_char reserved; // 0

	u_char addr_type; // enum SOCKS5_ADDR
	u_char addr[0];

	// u_char port[2];
};

struct socks5_connect_host {
	uint cmd; // client
	uint status; // server
	uint addr_type;
	ffstr addr;
	uint port;
};

static inline int socks5_connect_write(char *dst, size_t cap, const struct socks5_connect_host *c)
{
	FF_ASSERT(c->addr.len <= 255);
	uint n = 6 + (c->addr_type == SOCKS5_ADDR_HOST) + c->addr.len;
	if (n > cap)
		return 0;

	u_char *p = (u_char*)dst;
	*p++ = 5;
	*p++ = (c->cmd) ? c->cmd : c->status;
	*p++ = 0;
	*p++ = c->addr_type;

	if (c->addr_type == SOCKS5_ADDR_HOST)
		*p++ = c->addr.len;

	p = ffmem_copy(p, c->addr.ptr, c->addr.len);
	*(ushort*)p = ffint_be_cpu16(c->port);
	return n;
}

/**
Return N of bytes read */
static inline int socks5_connect_read(struct socks5_connect_host *c, const char *d, uint len)
{
	if (5 > len)
		return 0;

	const char *p = d;
	if (*p++ != 5)
		return -1; // 'version'

	c->cmd = c->status = *p++;

	if (*p++ != 0)
		return -1; // 'reserved'
	c->addr_type = *p++;

	uint n;
	switch (c->addr_type) {
	case SOCKS5_ADDR_IPV4: n = 4; break;
	case SOCKS5_ADDR_IPV6: n = 16; break;
	case SOCKS5_ADDR_HOST: n = *p++; break;
	default: return -1;
	}
	if (p + n + 2 > d + len)
		return 0;
	c->addr.ptr = (char*)p;
	c->addr.len = n;
	p += n;

	c->port = ffint_be_cpu16_ptr(p);
	if (!c->port)
		return -1;
	p += 2;
	return p - d;
}
