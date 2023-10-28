# OpenSSL

include ../config.mk

VER := 3.1.3
URL := https://www.openssl.org/source/openssl-$(VER).tar.gz
PKG := $(notdir $(URL))
DIR := openssl-$(VER)
LIB := $(DIR)/libssl.$(SO)

default: $(LIB)

# download
$(PKG):
	$(CURL) -o $@ $(URL)
	$(CURL) -o $@.sha1 $(URL).sha1
# 	sha1sum -c $@.sha1

# unpack
$(DIR): $(PKG)
	$(UNTAR_GZ) $<
	touch $@

# configure
CONFIGURE_FLAGS:=
ifeq "$(OS)" "windows"
	CONFIGURE_FLAGS := mingw64
endif
ifneq "$(CROSS_PREFIX)" ""
	CONFIGURE_FLAGS += --cross-compile-prefix=$(CROSS_PREFIX)
endif

$(DIR)/Makefile: $(DIR)
	cd $(DIR) && ./Configure $(CONFIGURE_FLAGS)

# build
$(LIB): $(DIR)/Makefile
	cd $(DIR) && $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN)"
ifeq "$(OS)" "windows"
	cd $(DIR) && x86_64-w64-mingw32-strip libcrypto-3-x64.dll libssl-3-x64.dll
	cd $(DIR) && mv libcrypto-3-x64.dll libssl-3-x64.dll ..
else
	cd $(DIR) && strip libcrypto.so.3 libssl.so.3
	cd $(DIR) && mv libcrypto.so libssl.so libcrypto.so.3 libssl.so.3 ..
endif
