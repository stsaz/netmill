# OpenSSL

include ../config.mk

VER := 3.5.6
URL := https://github.com/openssl/openssl/releases/download/openssl-$(VER)/openssl-$(VER).tar.gz
PKG := $(NML_3PT)/openssl/$(notdir $(URL))
SHA1 := 3dc26853ca7683237a869d01745dae48fb63ed82
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
	echo "$(SHA1) *$(PKG)" | sha1sum -c -

# unpack
$(DIR): $(PKG)
	$(UNTAR_GZ) $<

# configure
CONFIGURE_FLAGS:=
ifeq "$(CPU)" "amd64"
	ifeq "$(SYS)" "android"
		CONFIGURE_FLAGS := android-x86_64 -D__ANDROID_API__=$(A_API)
	else ifeq "$(OS)" "windows"
		CONFIGURE_FLAGS := mingw64 --cross-compile-prefix=x86_64-w64-mingw32-
	endif
else ifeq "$(CPU)" "arm64"
	ifeq "$(SYS)" "android"
		CONFIGURE_FLAGS := android-arm64 -D__ANDROID_API__=$(A_API)
	endif
endif

$(DIR)/Makefile: | $(DIR)
	cd $(DIR) && ./Configure $(CONFIGURE_FLAGS)

# build
$(LIB): $(DIR)/Makefile
	cd $(DIR) && $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN) $(LINKFLAGS_USER)" || true
	cd $(DIR) && $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN) $(LINKFLAGS_USER)" $@
ifeq "$(OS)" "windows"
	cd $(DIR) && $(STRIP) libcrypto-3-x64.dll libssl-3-x64.dll
	cd $(DIR) && mv libcrypto-3-x64.dll libssl-3-x64.dll ..
else ifeq "$(SYS)" "linux"
	cd $(DIR) && $(STRIP) libcrypto.so.3 libssl.so.3
	cd $(DIR) && mv libcrypto.so libssl.so libcrypto.so.3 libssl.so.3 ..
else
	cd $(DIR) && $(STRIP) libcrypto.so libssl.so
	cd $(DIR) && mv libcrypto.so libssl.so ..
endif
