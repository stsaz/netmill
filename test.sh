#!/bin/bash

# netmill tester

if test "$#" == "0" ; then
	echo "Usage: test.sh TEST"
	exit 1
fi

test_help() {
	./netmill -help
	./netmill cert help
	./netmill dns help
	./netmill firewall help
	./netmill http help
	./netmill service help
	./netmill url -help
}

$1
