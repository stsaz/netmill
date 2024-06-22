#!/bin/bash

# netmill tester

if test "$#" == "0" ; then
	echo "Usage: test.sh TEST"
	echo "Tests: all help http_local http_proxy dns_local dns_upstream dns_doh cert"
	exit 1
fi

set -xe

test_help() {
	./netmill -help
	./netmill cert help
	./netmill dns help
	./netmill http help
	./netmill service help
	./netmill url -help
}

test_kill_pid__filename() {
	local filename=$1
	if test -f $filename ; then
		pid=$(cat $filename)
		rm $filename
		kill -9 $pid || true
	fi
}

test_interrupt_pid__filename() {
	local filename=$1
	pid=$(cat $filename)
	kill $pid
	rm $filename
}

test_http_local() {
	# (re)start local file server
	test_kill_pid__filename nml.pid
	./netmill http  listen 8080  www . &
	echo $! >nml.pid
	sleep .5

	echo Normal download
	./netmill url "127.0.0.1:8080/README.md" -o nmltest/README.md
	diff README.md nmltest/README.md
	rm nmltest/README.md

	echo HEAD method
	./netmill url "127.0.0.1:8080/README.md" -check -method HEAD -print_headers

	echo Directory auto index
	./netmill url "127.0.0.1:8080/" -o nmltest/hs-dir.html
	cat nmltest/hs-dir.html

	echo 2 pipelined requests with 404 response

	cat <<EOF | nc 127.0.0.1 8080
GET /404-1 HTTP/1.1
Host: localhost:8080

GET /404-2 HTTP/1.1
Host: localhost:8080
Connection: close

EOF

	echo Bad request

cat <<EOF | nc 127.0.0.1 8080
bad request

EOF

	test_interrupt_pid__filename nml.pid
	sleep .5

	echo Connection refused
	./netmill url 127.0.0.1:8080/README.md -o nmltest/README.md || true
}

test_https_local() {
	if ! test -f nmltest/htsv.pem ; then
		./netmill cert generate \
			subject "CN=netmill.test" \
			output "nmltest/htsv.pem"
	fi

	# (re)start local file server
	test_kill_pid__filename nml.pid
	./netmill http \
		listen "8080" \
		cert "nmltest/htsv.pem" \
		www "." &
	echo $! >nml.pid
	sleep .5

	echo Download via TLS
	rm -f nmltest/README.md
	./netmill url "https://127.0.0.1:8080/README.md" -trust -o "nmltest/README.md"
	diff README.md nmltest/README.md
	rm nmltest/README.md

	test_interrupt_pid__filename nml.pid
}

test_http_proxy() {
	# (re)start local file server
	test_kill_pid__filename nml.pid
	./netmill http  listen 8080  threads 1  www . &
	echo $! >nml.pid

	# (re)start proxy server
	test_kill_pid__filename nml2.pid
	./netmill http  listen 8181  threads 1  proxy &
	echo $! >nml2.pid
	sleep .5

	echo Normal download via proxy

	./netmill url "127.0.0.1:8080/README.md" -o "nmltest/README.md" \
		-proxy "127.0.0.1:8181"
	diff README.md nmltest/README.md

	echo 'Repeat download via existing (cached) connection'

	rm -f nmltest/README.md
	./netmill url "127.0.0.1:8080/README.md" -o "nmltest/README.md" \
		-proxy "127.0.0.1:8181"
	diff README.md nmltest/README.md
	rm nmltest/README.md

# 	echo POST request via proxy

# 	cat <<EOF | nc 127.0.0.1 8181 >/dev/null
# POST http://localhost:8080/ HTTP/1.1
# Host: localhost:8080
# Content-Length: 18
# Client-Header: Value

# hello from client
# EOF

	test_interrupt_pid__filename nml.pid

	echo Chunked response from upstream

	cat <<EOF | nc -l 127.0.0.1 8080 &
HTTP/1.1 200 OK UPSTREAM
Server: upstream
Transfer-Encoding: chunked
Upstream-Header: Value
Connection: close

2
he
3
llo
0

EOF
	sleep .5
	./netmill url "127.0.0.1:8080/README.md" -o "nmltest/README.md" \
		-proxy "127.0.0.1:8181" \
		-print_headers
	kill $! || true

	test_interrupt_pid__filename nml2.pid
}

test_http_proxy_tunnel() {
	# (re)start proxy server
	test_kill_pid__filename nml2.pid
	./netmill http  listen 8181  threads 1  proxy &
	echo $! >nml2.pid
	sleep .5

	echo Tunnel

	cat <<EOF | nc -l 127.0.0.1 8080 &
output-data
EOF
	sleep .5
	cat <<EOF | nc 127.0.0.1 8181
CONNECT localhost:8080 HTTP/1.1
Host: localhost:8080

input-data
EOF
	kill $! || true

	test_interrupt_pid__filename nml2.pid
}

test_dns_local() {
	# (re)start DNS server with local hosts file
	test_kill_pid__filename nml.pid
	echo 'block.com' >nmltest/hosts
	./netmill -D dns \
		listen 127.0.0.1:5353 \
		hosts nmltest/hosts &
	echo $! >nml.pid
	sleep .5

	# resolve blocked host
	dig @127.0.0.1 -p 5353 block.com

	# resolve unknown host
	dig @127.0.0.1 -p 5353 unknown.com

	rm nmltest/hosts
	test_interrupt_pid__filename nml.pid
}

test_dns_upstream() {
	# (re)start DNS server with local hosts file
	test_kill_pid__filename nml.pid
	echo 'block.com' >nmltest/hosts
	./netmill -D dns \
		listen 127.0.0.1:5353 \
		hosts nmltest/hosts &
	echo $! >nml.pid

	# (re)start DNS server with upstream server
	test_kill_pid__filename nml2.pid
	./netmill -D dns \
		listen 127.0.0.1:5454 \
		upstream 127.0.0.1:5353 &
	echo $! >nml2.pid
	sleep .5

	# resolve blocked host
	dig @127.0.0.1 -p 5454 block.com

	# resolve unknown host
	dig @127.0.0.1 -p 5454 unknown.com

	rm nmltest/hosts
	test_interrupt_pid__filename nml.pid
	test_interrupt_pid__filename nml2.pid
}

test_dns_doh() {
	echo '8.8.8.8 dns.google' >nmltest/hosts

	# (re)start DNS server with DoH upstream server
	test_kill_pid__filename nml.pid
	./netmill -D dns \
		listen 127.0.0.1:5454 \
		hosts nmltest/hosts \
		upstream https://dns.google &
	echo $! >nml.pid
	sleep .5

	dig @127.0.0.1 -p 5454 google.com

	rm nmltest/hosts
	test_interrupt_pid__filename nml.pid
}

test_cert() {
	./netmill cert generate \
		subject CN=netmill.test \
		output nmltest/cert.pem
	test -f nmltest/cert.pem
	rm nmltest/cert.pem
}

test_if() {
	./netmill if
}

test_all() {
	test_help
	test_http_local
	test_https_local
	test_http_proxy
	test_http_proxy_tunnel
	test_dns_local
	test_dns_upstream
	# test_dns_doh
	test_cert
	test_if
}

mkdir -p nmltest
rm -rf nmltest/*

while test "$#" != "0" ; do
	test_$1
	shift
done

rm -rf nmltest
echo DONE
