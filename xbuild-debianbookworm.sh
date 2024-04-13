#!/bin/bash

# netmill: cross-build on Linux for Debian-bookworm

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi

if ! podman container exists netmill_debianbookworm_build ; then
	if ! podman image exists netmill-debianbookworm-builder ; then
		# Create builder image
		cat <<EOF | podman build -t netmill-debianbookworm-builder -f - .
FROM debian:bookworm-slim
RUN apt update && \
 apt install -y \
  make
RUN apt install -y \
 gcc g++
RUN apt install -y \
 clang llvm
RUN apt install -y \
 libelf-dev \
 zstd unzip p7zip \
 cmake patch dos2unix curl
RUN apt install -y \
 netcat-traditional dnsutils
EOF
	fi

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 --name netmill_debianbookworm_build \
	 netmill-debianbookworm-builder \
	 bash -c 'cd /src/netmill && source ./build_linux.sh'
fi

# Prepare build script
cat >build_linux.sh <<EOF
set -xe

make -j8 zlib \
 -C ../ffpack

make -j8 openssl bpf xdp \
 -C 3pt

mkdir -p _linux-amd64
make -j8 \
 -C _linux-amd64 \
 -f ../Makefile \
 ROOT_DIR=../.. \
 $@
make -j8 app \
 -C _linux-amd64 \
 -f ../Makefile \
 ROOT_DIR=../..

cd _linux-amd64/netmill-0
bash /src/netmill/test.sh all
EOF

# Build inside the container
podman start --attach netmill_debianbookworm_build
