# Build third-party libraries

include config.mk
TGT_DIR := _$(SYS)-$(CPU)
ROOT := ../..

default:
	mkdir -p $(TGT_DIR)
	$(MAKE) build

build: openssl

LIB_OPENSSL := $(TGT_DIR)/libssl.$(SO)
ifeq "$(OS)" "windows"
	LIB_OPENSSL := $(TGT_DIR)/libssl-3-x64.$(SO)
endif
openssl: $(LIB_OPENSSL)

$(LIB_OPENSSL):
	$(MAKE) -I.. -C openssl
	cp openssl/*.$(SO)* $(TGT_DIR)


libbpf:
	git clone https://github.com/libbpf/libbpf

xdp-tools:
	git clone https://github.com/xdp-project/xdp-tools

xdp-tools/lib/libxdp/libxdp.a: libbpf xdp-tools
	cd xdp-tools/lib/libxdp && \
		VERBOSE=1 make -j8 libxdp.a STATIC_CFLAGS='-DLIBXDP_STATIC=1 -fPIC'

libxdp: xdp-tools/lib/libxdp/libxdp.a


hash:
	sha1sum -b \
		openssl/openssl-3.1.3.tar.gz \
		>packages.sha1

hash-check:
	sha1sum -c packages.sha1 --ignore-missing
