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
	./netmill firewall help
	./netmill http help
	./netmill service help
	./netmill url -help
}

test_kill_pid__filename() {
	local filename=$1
	if test -f $filename ; then
		pid=$(cat $filename)
		rm $filename
		kill -9 $pid
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

	# download
	./netmill url 127.0.0.1:8080/README.md -o nmltest/README.md
	diff README.md nmltest/README.md
	rm nmltest/README.md

	test_interrupt_pid__filename nml.pid
	sleep .5

	# connection refused
	./netmill url 127.0.0.1:8080/README.md -o nmltest/README.md || true
}

test_http_proxy() {
	# (re)start local file server
	test_kill_pid__filename nml.pid
	./netmill -D http  listen 8080  www . &
	echo $! >nml.pid

	# (re)start proxy server
	test_kill_pid__filename nml2.pid
	./netmill -D http  listen 8181  proxy &
	echo $! >nml2.pid
	sleep .5

	# download
	# ./netmill -D url 127.0.0.1:8181/README.md -o nmltest/README.md
	request='GET http://127.0.0.1:8080/README.md HTTP/1.1
Host: 127.0.0.1:8080
Connection: close

'
	nc 127.0.0.1 8181 <<<$request >nmltest/README.md
	diff README.md nmltest/README.md
	rm nmltest/README.md

	test_interrupt_pid__filename nml.pid
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

test_all() {
	test_help
	test_http_local
	test_http_proxy
	test_dns_local
	test_dns_upstream
	test_dns_doh
	test_cert
}

mkdir -p nmltest
rm -rf nmltest/*

test_$1

rm -rf nmltest
echo DONE
