# netmill

<img src="wind-mill.png" width="128" height="128">

netmill(*under development*) - network tools for Linux, Android, Windows.
You can use it as a standalone app or as a library via C and Java interface.
Current features:

* HTTP/1.1 server: local files, auto-index, virtual space, forward proxy (HTTP and tunelling)
* HTTP/1.1 client
* DNS server: hosts lists, hosts block lists, upstream servers, persistent cache
* Certificate generator

Contents:

* [HTTP Server](#http-server)
* [DNS Server](#dns-server)
* [Build](#build)
* [Install](#install)
* [Usage](#usage)
* [HTTP server as a library](#http-server-as-a-library)


## HTTP Server

HTTP/1.1 server features and limitations:

* Multi-threaded, uses all CPUs by default (Linux & Android only)
* Completely asynchronous file I/O (offload syscalls to other threads)
* Support active polling mode (experimental)
* HTTP/1.1 only
* Local files mode:
	* Serves the file tree in `www/` directory by default
	* Uses `index.html` as index file
	* Generates index document (directory contents)
	* Doesn't use sendfile()
	* No caching
	* No compression
	* No ETag, If-None-Match, Range
* Proxy mode:
	* Support tunnels (via CONNECT)
	* No request body
	* No outbound keep-alive
* SSE-optimized HTTP parser
* Configuration via command-line arguments; no configuration file required


## DNS Server

netmill DNS server has ad-blocking and caching capabilities.
It can be used as default DNS resolver on your system, blocking all attempts from any application to obtain an IP address of advertisment hosts.
The internal cache saves network traffic, and the logs provide you with the information of what hosts were resolved and how much time it took.

Features & limitations:

* Host list
	* Only one A or AAAA record per host
	* Block unwanted DNS names (e.g. DNS ads blocker)
	* Configure how to block them: with 127.0.0.1, 0.0.0.0 or NXDOMAIN, etc.
* DNS/UDP upstream servers
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


## Usage

Several examples:

```sh
# Run HTTP file-server on port `8080` with the current directory as root
netmill http  listen 8080  www .

# Run HTTP proxy-server
netmill http  listen 127.0.0.1:8080  proxy

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

# Download a file over HTTP
netmill url https://host.com/path/file
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


## Homepage

https://github.com/stsaz/netmill
