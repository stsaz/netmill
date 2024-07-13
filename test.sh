#!/bin/bash
# netmill tester

TESTS=(
	help
	http
		http_local https_local
		http_proxy https_proxy
	dns_local dns_upstream
	# dns_doh
	cert
	if
)

if test "$#" == "0" ; then
	echo "Usage: test.sh TEST..."
	echo "TEST: ${TESTS[@]}"
	exit 1
fi

CMDS=("$@")
if test "$1" == "all" ; then
	CMDS=("${TESTS[@]}")
fi

if test "$DEBUG" == 1 ; then
	DEBUG=-D
else
	DEBUG=
fi

set -e
if test "$V" == 1 ; then
	set -x
fi

test_help() {
	./netmill -help
	./netmill cert help
	./netmill dns help
	./netmill http help
	./netmill service help
	./netmill req -help
}

test_kill_pid__filename() {
	local filename=$1
	if test -f $filename ; then
		local pid=$(cat $filename)
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

	echo '### Normal download'
	./netmill req "127.0.0.1:8080/README.md" -o nmltest/README.md
	diff README.md nmltest/README.md
	rm nmltest/README.md

	echo '### HEAD method'
	./netmill req "127.0.0.1:8080/README.md" -check -method HEAD -print_headers

	echo '### Directory auto index'
	./netmill req "127.0.0.1:8080/" -o nmltest/hs-dir.html
	cat nmltest/hs-dir.html

	echo '### 2 pipelined requests with 404 response'

	cat <<EOF | nc 127.0.0.1 8080
GET /404-1 HTTP/1.1
Host: localhost:8080

GET /404-2 HTTP/1.1
Host: localhost:8080
Connection: close

EOF

	echo '### Bad request'

cat <<EOF | nc 127.0.0.1 8080
bad request

EOF

	test_interrupt_pid__filename nml.pid
	sleep .5

	echo '### Connection refused'
	./netmill req 127.0.0.1:8080/README.md -o nmltest/README.md || true
}

test_https_local() {
	if ! test -f nmltest/htsv.pem ; then
		./netmill cert generate \
			subject "CN=netmill.test" \
			output "nmltest/htsv.pem"
	fi

	# (re)start local file server
	test_kill_pid__filename nml.pid
	./netmill $DEBUG http \
		listen 4443 \
		threads 1 \
		cert "nmltest/htsv.pem" \
		www "." &
	echo $! >nml.pid
	sleep .5

	echo '### Download via TLS'
	rm -f nmltest/README.md
	./netmill req "https://127.0.0.1:4443/README.md" -trust -o "nmltest/README.md"
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
	./netmill $DEBUG http  listen 8181  threads 1  proxy &
	echo $! >nml2.pid
	sleep .5

	echo '### Normal download via proxy'

	./netmill req "127.0.0.1:8080/README.md" -o "nmltest/README.md" \
		-proxy "127.0.0.1:8181"
	diff README.md nmltest/README.md

	echo '### Repeat download via existing (cached) connection'

	rm -f nmltest/README.md
	./netmill req "127.0.0.1:8080/README.md" -o "nmltest/README.md" \
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

	echo '### Chunked response from upstream'

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
	rm -f nmltest/README.md
	local out=$(./netmill req "127.0.0.1:8080/README.md" -o "nmltest/README.md" \
		-proxy "127.0.0.1:8181" \
		-print_headers)
	grep "HTTP/1.1 200 OK UPSTREAM" <<<$out
	grep "Upstream-Header: Value" <<<$out
	test "$(cat nmltest/README.md)" == "hello"
	kill $! || true

	test_interrupt_pid__filename nml2.pid
}

test_https_proxy() {
	if ! test -f nmltest/htsv.pem ; then
		./netmill cert generate \
			subject "CN=netmill.test" \
			output "nmltest/htsv.pem"
	fi

	# (re)start local file server
	test_kill_pid__filename nml.pid
	./netmill $DEBUG http  \
		listen 4443 \
		threads 1 \
		cert "nmltest/htsv.pem" \
		www . &
	echo $! >nml.pid

	# (re)start proxy server
	test_kill_pid__filename nml2.pid
	./netmill $DEBUG http  listen 8181  threads 1  proxy &
	echo $! >nml2.pid
	sleep .5

	echo HTTPS request via HTTP proxy
	rm -f nmltest/README.md
	# ./netmill req "https://127.0.0.1:4443/README.md" -o "nmltest/README.md" \
	# 	-proxy "127.0.0.1:8181"
	curl -s -o "nmltest/README.md" -k \
		--proxy http://127.0.0.1:8181 \
		https://127.0.0.1:4443/README.md
	diff README.md nmltest/README.md
	rm nmltest/README.md

	test_interrupt_pid__filename nml.pid
	test_interrupt_pid__filename nml2.pid
}

test_http() {
	test_http_local
	test_http_proxy
	test_https_local
	test_https_proxy
}

test_dns_local() {
	# (re)start DNS server with local hosts file
	test_kill_pid__filename nml.pid
	echo 'block.com' >nmltest/hosts
	./netmill $DEBUG dns \
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
	./netmill $DEBUG dns \
		listen 127.0.0.1:5353 \
		hosts nmltest/hosts &
	echo $! >nml.pid

	# (re)start DNS server with upstream server
	test_kill_pid__filename nml2.pid
	./netmill $DEBUG dns \
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
	./netmill $DEBUG dns \
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

test_clean() {
	test_kill_pid__filename nml.pid
	test_kill_pid__filename nml2.pid
}

mkdir -p nmltest
rm -rf nmltest/*

for cmd in "${CMDS[@]}" ; do

	rm -rf ./nmltest/*
	test_$cmd

done

test_clean
rm -rf nmltest
echo DONE
