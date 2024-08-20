#!/bin/bash

# netmill: cross-build on Linux for Debian-bookworm

IMAGE_NAME=netmill-debianbookworm-builder
CONTAINER_NAME=netmill_debianbookworm_build
ARGS=${@@Q}

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi

if ! podman container exists $CONTAINER_NAME ; then
	if ! podman image exists $IMAGE_NAME ; then

		# Create builder image
		cat <<EOF | podman build -t $IMAGE_NAME -f - .
FROM debian:bookworm-slim
RUN apt update && \
 apt install -y \
  make
RUN apt install -y \
 perl \
 zstd zip unzip p7zip \
 cmake patch dos2unix curl
RUN apt install -y \
 netcat-traditional dnsutils
RUN apt install -y \
 gcc g++
RUN apt install -y \
 clang llvm
RUN apt install -y \
 libelf-dev
EOF
	fi

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 --name $CONTAINER_NAME \
	 $IMAGE_NAME \
	 bash -c 'cd /src/netmill && source ./build_linux.sh'
fi

# Prepare build script
cat >build_linux.sh <<EOF
set -xe

mkdir -p ../ffpack/_linux-amd64
make -j8 zlib \
 -C ../ffpack/_linux-amd64 \
 -f ../Makefile \
 -I ..

mkdir -p 3pt/_linux-amd64
make -j8 \
 -C 3pt/_linux-amd64 \
 -f ../Makefile \
 -I ..

make -j8 bpf xdp \
 -C 3pt

mkdir -p _linux-amd64
make -j8 \
 -C _linux-amd64 \
 -f ../Makefile \
 ROOT_DIR=../.. \
 $ARGS

cd _linux-amd64/netmill-0
bash /src/netmill/test.sh all
EOF

# Build inside the container
podman start --attach $CONTAINER_NAME
