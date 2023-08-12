# netmill

<img src="wind-mill.png" width="128" height="128">

netmill(*under development*) - HTTP/1.1 file/proxy server for Linux, Android, Windows.

netmill can also be used as a library (via C and Java interface) providing these features:

* HTTP/1.1 server: local files, auto-index, virtual space, forward proxy (HTTP and tunelling)
* HTTP/1.1 client

Later it may be expanded to include a variety of Internet features (not just HTTP) and network tools.

Contents:

* [Features](#features)
* [Build & Run](#build---run)
* [HTTP server as a library](#http-server-as-a-library)


## Features

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
	* No ETag, If-None-Match, Range
* Proxy mode:
	* Support tunnels (via CONNECT)
	* No request body
	* No outbound keep-alive
* stdout/stderr logging only
* SSE-optimized HTTP parser
* Basic command-line parameters; no configuration file


## Build & Run

[Build Instructions](BUILDING.md)

Run HTTP file-server on port 8080:

```sh
cd netmill-0
./netmill -l 8080
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
