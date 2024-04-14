#!/bin/bash

# netmill: cross-build on Linux for Alpine

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi

if ! podman container exists netmill_alpine_build ; then
	# Create builder image
	cat <<EOF | podman build -t netmill-alpine-builder -f - .
FROM alpine:3.18
RUN apk add \
 build-base \
 linux-headers
RUN apk add \
 clang llvm
RUN apk add \
 openssl openssl-dev
RUN apk add \
 elfutils-dev
EOF

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 --name netmill_alpine_build \
	 netmill-alpine-builder \
	 sh -c 'cd /src/netmill && source ./build_linux.sh'
fi

# Prepare build script
cat >build_linux.sh <<EOF
set -xe

make -j8 zlib \
 -C ../ffpack \
 BINDIR=_linux-musl-amd64

make -j8 bpf xdp \
 -C 3pt

mkdir -p _linux-musl-amd64
make -j8 \
 -C _linux-musl-amd64 \
 -f ../Makefile \
 ROOT_DIR=../.. \
 CFLAGS_USER=-DFF_MUSL \
 BINDIR=_linux-musl-amd64 \
 $@
EOF

# Build inside the container
podman start --attach netmill_alpine_build
