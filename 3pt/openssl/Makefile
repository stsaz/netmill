# OpenSSL

include ../config.mk

VER := 3.5.6
URL := https://github.com/openssl/openssl/releases/download/openssl-$(VER)/openssl-$(VER).tar.gz
PKG := $(NML_3PT)/openssl/$(notdir $(URL))
SHA1 := 3dc26853ca7683237a869d01745dae48fb63ed82
DIR := openssl-$(VER)
LIB := libssl.$(SO)
ifeq "$(OS)" "windows"
	LIB := libssl-3-x64.dll
else ifeq "$(SYS)" "linux"
	LIB := libssl.so.3
endif
ifeq "$(OS)" "linux"
	LINK_RPATH_ORIGIN_ESC := '-Wl,-rpath,\$$\$$ORIGIN'
endif

default: $(LIB)

# download
$(PKG):
	$(CURL) -o $@ $(URL)
	echo "$(SHA1) *$(PKG)" | $(SHA1SUM) -c -

# unpack
$(DIR): $(PKG)
	$(UNTAR_GZ) $<

# configure
CONFIGURE_FLAGS:=
ifeq "$(CPU)" "amd64"
	ifeq "$(SYS)" "android"
		CONFIGURE_FLAGS := android-x86_64
	else ifeq "$(OS)" "windows"
		CONFIGURE_FLAGS := mingw64 --cross-compile-prefix=x86_64-w64-mingw32-
	endif
else ifeq "$(CPU)" "arm64"
	ifeq "$(SYS)" "android"
		CONFIGURE_FLAGS := android-arm64
	else ifeq "$(OS)" "linux"
		CONFIGURE_FLAGS := linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu-
	endif
endif

$(DIR)/Makefile: | $(DIR)
	cd $(DIR) && ./Configure $(CONFIGURE_FLAGS)

# build
$(LIB): $(DIR)/Makefile
	cd $(DIR) && SOURCE_DATE_EPOCH=0 $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN_ESC) $(LINKFLAGS_USER)" || true
	cd $(DIR) && SOURCE_DATE_EPOCH=0 $(MAKE) LDFLAGS="$(LINK_RPATH_ORIGIN_ESC) $(LINKFLAGS_USER)" $@
ifeq "$(OS)" "windows"
	cd $(DIR) && $(STRIP) libcrypto-3-x64.dll libssl-3-x64.dll
	cd $(DIR) && mv libcrypto-3-x64.dll libssl-3-x64.dll ..
else ifeq "$(SYS)" "linux"
	cd $(DIR) && $(STRIP) libcrypto.so.3 libssl.so.3
	cd $(DIR) && mv libcrypto.so libssl.so libcrypto.so.3 libssl.so.3 ..
else ifeq "$(OS)" "apple"
	cd $(DIR) && install_name_tool -id @loader_path/libssl.dylib libssl.dylib
	cd $(DIR) && install_name_tool -id @loader_path/libcrypto.dylib libcrypto.dylib
	cd $(DIR) && install_name_tool -change /usr/local/lib/libcrypto.3.dylib @loader_path/libcrypto.dylib libssl.dylib
	cd $(DIR) && install_name_tool -change /usr/local/lib/libssl.3.dylib @loader_path/libssl.dylib libcrypto.dylib
	cd $(DIR) && $(STRIP) -x libcrypto.dylib libssl.dylib
	cd $(DIR) && mv libcrypto.dylib libssl.dylib libcrypto.3.dylib libssl.3.dylib ..
else
	cd $(DIR) && $(STRIP) libcrypto.$(SO) libssl.$(SO)
	cd $(DIR) && mv libcrypto.$(SO) libssl.$(SO) ..
endif
