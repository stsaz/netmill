# Build third-party libraries

export NML_3PT := $(dir $(firstword $(MAKEFILE_LIST)))
include config.mk

default: openssl

LIB_OPENSSL := libssl.$(SO)
ifeq "$(OS)" "windows"
	LIB_OPENSSL := libssl-3-x64.$(SO)
endif
openssl: $(LIB_OPENSSL)
$(LIB_OPENSSL):
	$(MAKE) -f $(NML_3PT)/openssl/Makefile


libbpf:
	git clone --depth=1 https://github.com/libbpf/libbpf

libbpf/src/libbpf.so: libbpf
	cd libbpf/src && \
		VERBOSE=1 $(MAKE) AR=ar

bpf: libbpf/src/libbpf.so

xdp-tools:
	git clone --depth=1 https://github.com/xdp-project/xdp-tools
	cd xdp-tools/lib/libxdp && \
		patch -p1 <../../../xdp.patch

xdp-tools/lib/libxdp/libxdp.a: libbpf xdp-tools
	cp -au libbpf/src/*.h \
		xdp-tools/headers/bpf
	cd xdp-tools/lib/libxdp && \
		VERBOSE=1 $(MAKE) staticobjs/libxdp.o staticobjs/xsk.o \
			STATIC_CFLAGS='-DLIBXDP_STATIC=1 -fPIC' && \
		$(AR) rcs libxdp.a \
			staticobjs/libxdp.o staticobjs/xsk.o

xdp: xdp-tools/lib/libxdp/libxdp.a

xdp-clean:
	cd xdp-tools/lib/libxdp && \
		make clean


hash:
	sha1sum -b \
		openssl/openssl-3.1.3.tar.gz \
		>packages.sha1

hash-check:
	sha1sum -c packages.sha1 --ignore-missing
