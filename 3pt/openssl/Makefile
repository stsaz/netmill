# OpenSSL

include ../config.mk

VER := 3.1.3
URL := https://www.openssl.org/source/openssl-$(VER).tar.gz
PKG := $(notdir $(URL))
DIR := openssl-$(VER)
LIB := libssl.$(SO)

default: $(DIR)
	cd $(DIR) && ./Configure
	$(MAKE) $(LIB)

# download
$(PKG):
	$(CURL) -o $@ $(URL)
	$(CURL) -o $@.sha1 $(URL).sha1
# 	sha1sum -c $@.sha1

# unpack
$(DIR): $(PKG)
	$(UNTAR_GZ) $<
	touch $@

$(LIB):
	cd $(DIR) && $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN)"
	strip libcrypto.so.3 libssl.so.3
