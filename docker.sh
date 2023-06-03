# netmill: build app on Alpine; build container

set -xe

if test "$1" == "create" ; then
	cat <<EOF | sudo docker build -t alpine-c-builder:latest -
FROM alpine:3.18
RUN apk add --no-cache build-base
EOF
	sudo docker create -it -v /tmp/src:/src alpine-c-builder --name alpine_c_builder
	exit 0
fi

if test "$1" == "start" ; then
	sudo docker start -ai alpine_c_builder
	exit 0
fi

SRC=$1
mkdir -p /tmp/src
cp -rua $SRC/ffbase $SRC/ffos $SRC/netmill /tmp/src
sudo docker container exec -it alpine_c_builder make -j8 -C /src/netmill CFLAGS_USER=-DFF_MUSL
cd /tmp/src/netmill
sudo make docker
