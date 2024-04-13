# netmill

<img src="wind-mill.png" width="128" height="128">

netmill - network tools for Linux, Android, Windows.
You can use it as a standalone app or as a library via C and Java interface.
Current features:

* HTTP/1.1 Server: SSL, local files, auto-index, virtual space, forward proxy (HTTP and tunelling)
* HTTP/1.1 Client: SSL
* DNS Server: hosts lists, hosts block lists, upstream servers (UDP, DoH), persistent cache
* X509 Certificate Generator
* Ingress Firewall (XDP/Linux)
* ping (XDP/Linux)

Contents:

* [HTTP Server](#http-server)
* [HTTP Client](#http-client)
* [DNS Server](#dns-server)
* [Ingress Firewall](#ingress-firewall)
* [XDP ping](#xdp-ping)
* [Certificate Generator](#certificate-generator)
* [Build](#build)
* [Install](#install)
* [HTTP server as a library](#http-server-as-a-library)


## HTTP Server

Examples:

```sh
# Run HTTP file-server on port `8080` with the current directory as root
netmill http  listen 8080  www .

# Run HTTP proxy-server
netmill http  listen 127.0.0.1:8080  proxy
```

Features:

* Multi-threaded, uses all CPUs by default (Linux & Android only)
* Completely asynchronous file I/O (offload syscalls to other threads)
* Support active polling mode (experimental)
* Local files mode:
	* Serves the file tree in `www/` directory by default
	* Uses `index.html` as index file
	* Generates index document (directory contents)
* Proxy mode:
	* Support tunnels (via CONNECT)
* SSE-optimized HTTP parser
* Configuration via command-line arguments; no configuration file required

Limitations:

* Local files mode:
	* Doesn't use sendfile()
	* No caching
	* No compression
	* No ETag, If-None-Match, Range
* Proxy mode:
	* No request body
	* No outbound keep-alive

* HTTP/1.1 only (no HTTP/2)


## HTTP Client

Examples:

```sh
# Download a file over HTTP
netmill url https://host.com/path/file
```

Features:

* Plain HTTP and HTTPS

Limitations:

* No request body
* No server certificate verification


## DNS Server

netmill DNS server has ad-blocking and caching capabilities.
It can be used as default DNS resolver on your system, blocking all attempts from any application to obtain an IP address of advertisment hosts.
The internal cache saves network traffic, and the logs provide you with the information of what hosts were resolved and how much time it took.

Features:

* Host list
	* Only one A or AAAA record per host
	* Block unwanted DNS names (e.g. DNS ads blocker)
	* Configure how to block them: with 127.0.0.1, 0.0.0.0 or NXDOMAIN, etc.
* UDP and DNS-over-HTTPS upstream servers
* Persistent file cache

You can use many separate files as host lists, or all in one.  Syntax example:

```sh
# Some comment
! Another comment

# Respond with 127.0.0.1 IP address for "localhost" and "mycomputer",
#  but not their subdomains, e.g. "sub.localhost" or "sub.mycomputer"
# These rules have the highest priority
127.0.0.1 localhost mycomputer

# Block hosts and all their subdomains
block.com block2.com
||block3.com^

# Unblock host which was blocked by the previous line
+un.block.com
````

Examples:

* (Optional) Use netmill as default DNS server on Fedora:

	```sh
	# Disable preinstalled DNS server
	sudo systemctl stop systemd-resolved
	sudo systemctl disable systemd-resolved
	sudo mv /etc/resolv.conf{,.backup}
	# Now set 127.0.0.1 as DNS server in Network Manager, then restart network
	```

Example: run container with netmill with ad-blocking, caching DNS proxy securely connected to Google Public DNS:

```sh
cd ~/bin/netmill-0
mkdir -p ./log ./dns-hosts ./dns-cache
echo '8.8.8.8 dns.google' >./dns-hosts/hosts.txt
# Download lists with the host names to block
wget https://adaway.org/hosts.txt -O ./dns-hosts/adaway-hosts.txt
wget https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt -O ./dns-hosts/adguardteam-filter.txt

cat <<EOF | sudo docker build -t netmill-dns -f - .
FROM netmill:alpine
ENTRYPOINT []
CMD /netmill-0/netmill \
 -log        /netmill-0/log/dns.log \
 dns \
 aaaa-block \
 hosts       /netmill-0/dns-hosts/hosts.txt \
 hosts       /netmill-0/dns-hosts/adaway-hosts.txt \
 hosts       /netmill-0/dns-hosts/adguardteam-filter.txt \
 monitor \
 cache-dir   /netmill-0/dns-cache \
 min-ttl     60 \
 error-ttl   60 \
 upstream    https://dns.google
EOF

sudo docker create \
 --restart always \
 -p 53:53/udp \
 --name netmill_dns \
 netmill-dns
sudo docker start netmill_dns
```

More examples:

```sh
# Run DNS proxy-server with 1 hosts list, 1 upstream server and persistent cache
sudo netmill dns \
 listen 127.0.0.1 \
 hosts /etc/hosts \
 upstream 8.8.8.8 \
 cache-dir /var/cache/dns

# Install DNS server service
sudo netmill service install \
 `which netmill` dns  listen 127.0.0.1  ...
sudo systemctl start netmill
sudo systemctl status netmill
sudo systemctl enable netmill
```


## Ingress Firewall

Blocks certain type of incoming traffic and redirects raw packets to userspace for (potential) inspection.
The underlying technology is Linux XDP, so this means that the redirected packets don't reach the kernel network stack.

```sh
# Redirect all incoming TCP:443
netmill firewall interface eth1 \
	ip_proto TCP \
	l4_dst_port 443

# Redirect all incoming ICMP
netmill firewall interface eth1 \
	ip_proto ICMP
```


## XDP ping

ping utility uses XDP/Linux.
Hardware addresses must be manually specified and must be real.

```sh
# Start sending ICMP packets to 10.1.1.2
netmill ping interface eth1 \
	hwsrc 11:11:11:11:11:11 \
	hwdst 22:22:22:22:22:22 \
	src 10.1.1.1 \
	dst 10.1.1.2
```


## Certificate Generator

```sh
# Generate RSA key and X509 certificate PEM file
netmill cert \
 bits 2048 \
 subject "/CN=hostname" \
 until "2030-01-01 00:00:00" \
 output cert.pem
```


## Build

[Build Instructions](BUILDING.md)


## Install

Linux:

* Unpack the archive somewhere, e.g. to `~/bin`:

	```sh
	mkdir -p ~/bin
	tar xf netmill-VERSION-linux-amd64.tar.zst -C ~/bin
	```

* Create a symbolic link:

	```sh
	ln -s ~/bin/netmill-0/netmill ~/bin/netmill
	```


## HTTP server as a library

The program interface allows you to run netmill HTTP server from your own project and configure everything, even choosing the filters that process HTTP requests.
You may also place your own filters into the HTTP request processing conveyor.

Pseudo code for starting netmill HTTP server with 'virtspace' plugin:

```C
#include <netmill.h>

#include <http-server/{FILTER}.h>
// ...
static const struct nml_filter* filters[] = {
	&nml_filter_{FILTER},
	// ...
	NULL
};

struct nml_http_server_conf sc;
nml_http_server_conf(NULL, &sc);
// sc.option = ...;

static const struct nml_handler handlers[] = {
	{ "/", "GET", root_handler },
	{}
};
nml_http_virtspace_init(&sc, handlers);

sc.filters = filters;

nml_http_server *s = nml_http_server_new();
nml_http_server_conf(s, sc);
nml_http_server_run(s);
```


## External Libraries

[openssl](https://www.openssl.org),
[zlib](https://www.zlib.net)


## License

BSD 2-Clause
