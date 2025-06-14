#!/bin/bash

# netmill: cross-build on Linux for Linux/AMD64 | Windows/AMD64

IMAGE_NAME=netmill-debianbw-builder
CONTAINER_NAME=netmill_debianBW_build
BUILD_TARGET=linux
if test "$OS" == "windows" ; then
	IMAGE_NAME=netmill-win64-builder
	CONTAINER_NAME=netmill_win64_build
	BUILD_TARGET=mingw64
fi
ARGS=${@@Q}

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi

if ! podman container exists $CONTAINER_NAME ; then
	if ! podman image exists $IMAGE_NAME ; then

		# Create builder image
		if test "$OS" == "windows" ; then

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
 gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
EOF

		else

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
	fi

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 --name $CONTAINER_NAME \
	 $IMAGE_NAME \
	 bash -c "cd /src/netmill && source ./build_$BUILD_TARGET.sh"
fi

if ! podman container top $CONTAINER_NAME ; then
	cat >build_$BUILD_TARGET.sh <<EOF
sleep 600
EOF
	# Start container in background
	podman start --attach $CONTAINER_NAME &
	# Wait until the container is ready
	sleep .5
	while ! podman container top $CONTAINER_NAME ; do
		sleep .5
	done
fi

# Prepare build script

ARGS_OS=""
ODIR=_linux-amd64
XDP_ENABLE=1
TESTS_RUN=1

if test "$OS" == "windows" ; then
	ARGS_OS="OS=windows \
COMPILER=gcc \
CROSS_PREFIX=x86_64-w64-mingw32-"
	ODIR=_windows-amd64
	XDP_ENABLE=0
	TESTS_RUN=0
fi

cat >build_$BUILD_TARGET.sh <<EOF
set -xe

mkdir -p ../ffpack/$ODIR
make -j8 zlib \
 -C ../ffpack/$ODIR \
 -f ../Makefile \
 -I .. \
 $ARGS_OS

mkdir -p 3pt/$ODIR
make -j8 \
 -C 3pt/$ODIR \
 -f ../Makefile \
 -I .. \
 $ARGS_OS

if test "$XDP_ENABLE" == "1" ; then
	make -j8 bpf xdp \
	 -C 3pt
fi

mkdir -p $ODIR
make -j8 \
 -C $ODIR \
 -f ../Makefile \
 ROOT_DIR=../.. \
 $ARGS_OS \
 CFLAGS_USER=-fno-diagnostics-color \
 $ARGS

if test "$TESTS_RUN" == "1" ; then
	cd $ODIR/netmill-0
	bash /src/netmill/test.sh all
fi
EOF

# Build inside the container
podman exec $CONTAINER_NAME \
 bash -c "cd /src/netmill && source ./build_$BUILD_TARGET.sh"
