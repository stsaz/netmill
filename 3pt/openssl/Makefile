# OpenSSL

include ../config.mk

VER := 3.1.3
URL := https://www.openssl.org/source/openssl-$(VER).tar.gz
PKG := $(NML_3PT)/openssl/$(notdir $(URL))
DIR := openssl-$(VER)
LIB := libssl.so
ifeq "$(OS)" "windows"
	LIB := libssl-3-x64.dll
else ifeq "$(SYS)" "linux"
	LIB := libssl.so.3
endif

default: $(LIB)

# download
$(PKG):
	$(CURL) -o $@ $(URL)
	$(CURL) -o $@.sha1 $(URL).sha1
# 	sha1sum -c $@.sha1

# unpack
$(DIR): $(PKG)
	$(UNTAR_GZ) $<

# configure
CONFIGURE_FLAGS:=
ifeq "$(CPU)" "amd64"
	ifeq "$(SYS)" "android"
		CONFIGURE_FLAGS := android-x86_64 -D__ANDROID_API__=$(A_API)
	else ifeq "$(OS)" "windows"
		CONFIGURE_FLAGS := mingw64
	endif
else ifeq "$(CPU)" "arm64"
	ifeq "$(SYS)" "android"
		CONFIGURE_FLAGS := android-arm64 -D__ANDROID_API__=$(A_API)
	endif
endif
ifneq "$(CROSS_PREFIX)" ""
	CONFIGURE_FLAGS += --cross-compile-prefix=$(CROSS_PREFIX)
endif

$(DIR)/Makefile: | $(DIR)
	cd $(DIR) && ./Configure $(CONFIGURE_FLAGS)

# build
$(LIB): $(DIR)/Makefile
	cd $(DIR) && $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN)" || true
	cd $(DIR) && $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN)" $@
ifeq "$(OS)" "windows"
	cd $(DIR) && $(STRIP) libcrypto-3-x64.dll libssl-3-x64.dll
	cd $(DIR) && mv libcrypto-3-x64.dll libssl-3-x64.dll ..
else ifeq "$(SYS)" "linux"
	cd $(DIR) && ln -s libssl.so.3 libssl.so
	cd $(DIR) && ln -s libcrypto.so.3 libcrypto.so
	cd $(DIR) && $(STRIP) libcrypto.so.3 libssl.so.3
	cd $(DIR) && mv libcrypto.so libssl.so libcrypto.so.3 libssl.so.3 ..
else
	cd $(DIR) && $(STRIP) libcrypto.so libssl.so
	cd $(DIR) && mv libcrypto.so libssl.so ..
endif
