#!/bin/bash

# netmill: cross-build on Linux for Windows/AMD64

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi

if ! podman container exists netmill_win64_build ; then
	# Create builder image
	cat <<EOF | podman build -t netmill-win64-builder -f - .
FROM debian:bookworm-slim
RUN apt update && \
 apt install -y \
  make
RUN apt install -y \
 gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
RUN apt install -y \
 perl \
 zstd zip unzip \
 cmake patch dos2unix curl
EOF

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 --name netmill_win64_build \
	 netmill-win64-builder \
	 bash -c 'cd /src/netmill && source ./build_win64.sh'
fi

# Prepare build script
cat >build_win64.sh <<EOF
set -xe

make -j8 zlib \
 -C ../ffpack

make -j8 openssl \
 -C 3pt \
 OS=windows \
 COMPILER=gcc \
 CROSS_PREFIX=x86_64-w64-mingw32-

mkdir -p _windows-amd64
make -j8 \
 -C _windows-amd64 \
 -f ../Makefile \
 ROOT_DIR=../.. \
 OS=windows \
 COMPILER=gcc \
 CROSS_PREFIX=x86_64-w64-mingw32- \
 CFLAGS_USER=-fno-diagnostics-color \
 $@
make -j8 app \
 -C _windows-amd64 \
 -f ../Makefile \
 ROOT_DIR=../.. \
 OS=windows
EOF

# Build inside the container
podman start --attach netmill_win64_build
