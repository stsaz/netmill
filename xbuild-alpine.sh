#!/bin/bash

# netmill: cross-build on Linux for Alpine

IMAGE_NAME=netmill-alpine-builder
CONTAINER_NAME=netmill_alpine_build
ARGS=${@@Q}

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi

if ! podman container exists $CONTAINER_NAME ; then
	if ! podman image exists $IMAGE_NAME ; then

		# Create builder image
		cat <<EOF | podman build -t $IMAGE_NAME -f - .
FROM alpine:3.18
RUN apk add \
 build-base \
 linux-headers
RUN apk add \
 openssl openssl-dev
EOF
	fi

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 --name $CONTAINER_NAME \
	 $IMAGE_NAME \
	 sh -c 'cd /src/netmill && source ./build_linux.sh'
fi

# Prepare build script
cat >build_linux.sh <<EOF
set -xe

make -j8 zlib \
 -C ../ffpack \
 BINDIR=_linux-musl-amd64

mkdir -p _linux-musl-amd64
make -j8 \
 -C _linux-musl-amd64 \
 -f ../Makefile \
 ROOT_DIR=../.. \
 CFLAGS_USER=-DFF_MUSL \
 BINDIR=_linux-musl-amd64 \
 $ARGS
EOF

# Build inside the container
podman start --attach $CONTAINER_NAME
