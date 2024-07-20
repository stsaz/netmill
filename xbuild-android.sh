#!/bin/bash

# netmill: cross-build on Linux for Android

# ANDROID_HOME=
# ANDROID_CLT_URL=
# ANDROID_BT_VER=
# ANDROID_PF_VER=
# ANDROID_NDK_VER=
# GRADLE_DIR=
# CPU=
IMAGE_NAME=netmill-android-builder
CONTAINER_NAME=netmill_android_build
ARGS=${@@Q}

set -xe

if ! test -d "../netmill" ; then
	exit 1
fi
NML_DIR=$(pwd)

if test -z "$ANDROID_HOME" ; then
	exit 1
elif ! test -d "$ANDROID_HOME/cmdline-tools" ; then
	# Download and unpack Android tools
	mkdir -p /tmp/android-dl
	cd /tmp/android-dl
	if test -z "$ANDROID_CLT_URL" ; then
		exit 1
	fi
	wget $ANDROID_CLT_URL

	cd $ANDROID_HOME
	mkdir cmdline-tools
	cd cmdline-tools
	fcom unpack /tmp/android-dl/commandlinetools*
	mv cmdline-tools latest
	cd $NML_DIR
fi

if ! test -d "$ANDROID_HOME/platforms/android-$ANDROID_PF_VER" ; then
	# Download and install Android SDK
	cd $ANDROID_HOME/cmdline-tools/latest/bin
	./sdkmanager --list
	if test -z "$ANDROID_PF_VER" ; then
		exit 1
	elif test -z "$ANDROID_BT_VER" ; then
		exit 1
	elif test -z "$ANDROID_NDK_VER" ; then
		exit 1
	fi
	./sdkmanager \
	 "platform-tools" \
	 "platforms;android-$ANDROID_PF_VER" \
	 "build-tools;$ANDROID_BT_VER" \
	 "ndk;$ANDROID_NDK_VER"
	cd $NML_DIR
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
 openjdk-17-jdk
EOF
	fi

	if test -z "$GRADLE_DIR" ; then
		exit 1
	fi

	# Create builder container
	podman create --attach --tty \
	 -v `pwd`/..:/src \
	 -v $ANDROID_HOME:/Android \
	 -v $GRADLE_DIR:/root/.gradle \
	 --name $CONTAINER_NAME \
	 $IMAGE_NAME \
	 bash -c 'cd /src/netmill && source ./build_android.sh'
fi

if ! podman container top $CONTAINER_NAME ; then
	cat >build_android.sh <<EOF
sleep 600
EOF
	# Start container in background
	podman start --attach $CONTAINER_NAME &
	sleep .5
	while ! podman container top $CONTAINER_NAME ; do
		sleep .5
	done
fi

# Prepare build script
cat >build_android.sh <<EOF
set -xe

export ANDROID_HOME=/Android
mkdir -p _android-$CPU
make -j8 \
 -C _android-$CPU \
 -f ../android/Makefile \
 -I ../android \
 ROOT_DIR=../.. \
 NDK_VER=$ANDROID_NDK_VER \
 CPU=$CPU \
 A_API=26 \
 $ARGS
EOF

# Build inside the container
podman exec $CONTAINER_NAME \
 bash -c 'cd /src/netmill && source ./build_android.sh'
