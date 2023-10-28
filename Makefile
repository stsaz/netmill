# netmill Makefile

ROOT_DIR := ..
NETMILL := $(ROOT_DIR)/netmill
FFBASE := $(ROOT_DIR)/ffbase
FFOS := $(ROOT_DIR)/ffos

include $(FFBASE)/conf.mk

SUBMAKE := $(MAKE) -f $(firstword $(MAKEFILE_LIST))

EXE := netmill
APP_DIR := netmill-0
ifeq "$(OS)" "windows"
	EXE := netmill.exe
endif


CFLAGS := -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-multichar
ifeq "$(COMPILER)" "gcc"
	CFLAGS += -Wno-nonnull -Wno-array-bounds -Wno-stringop-overflow
endif
CFLAGS += -DFFBASE_HAVE_FFERR_STR
CFLAGS += -MMD -MP
CFLAGS += -I$(NETMILL)/src -I$(FFOS) -I$(FFBASE)
CFLAGS += -g
ifeq "$(DEBUG)" "1"
	CFLAGS += -DNML_ENABLE_LOG_EXTRA -DFF_DEBUG -O0
else
	CFLAGS += -O3 -fno-strict-aliasing
endif
ifeq "$(ASAN)" "1"
	CFLAGS += -fsanitize=address -DFFBASE_MEM_ASAN
	LINKFLAGS += -fsanitize=address
endif
ifneq "$(CPU_OLD)" "1"
	CFLAGS += -march=nehalem
endif
ifeq "$(OS)" "windows"
	LINKFLAGS += -lws2_32
endif
CFLAGS += $(CFLAGS_USER)
LINKFLAGS += $(LINKFLAGS_USER)


default: $(EXE)
ifneq "$(DEBUG)" "1"
	$(SUBMAKE) strip-debug
endif
	$(SUBMAKE) app

-include $(wildcard *.d)

EXE_OBJ := \
	exe-main.o \
	exe-cert.o \
	exe-dns.o \
	exe-http.o \
	exe-url.o
EXE_OBJ += \
	worker.o \
	tcp-listener.o udp-listener.o \
	nif.o

include $(NETMILL)/src/dns-server/Makefile
include $(NETMILL)/src/http-client/Makefile
include $(NETMILL)/src/http-server/Makefile

%.o: $(NETMILL)/src/%.c
	$(C) $(CFLAGS) $< -o $@

EXE_OBJ += ffssl.o
CFLAGS_OPENSSL := $(CFLAGS) -Wno-deprecated-declarations
ifeq "$(OS)" "windows"
	CFLAGS_OPENSSL += -I$(NETMILL)/3pt/openssl/openssl-3.1.3/include
	LINKFLAGS += -L$(NETMILL)/3pt/_$(OS)-$(CPU) -lssl-3-x64 -lcrypto-3-x64
	LIBS3 += \
		$(NETMILL)/3pt/_$(OS)-$(CPU)/libssl-3-x64.dll \
		$(NETMILL)/3pt/_$(OS)-$(CPU)/libcrypto-3-x64.dll
else
	LINKFLAGS += -lssl -lcrypto
endif
ffssl.o: $(NETMILL)/src/util/ffssl.c
	$(C) $(CFLAGS_OPENSSL) $< -o $@

exe-%.o: $(NETMILL)/src/exe/%.c
	$(C) $(CFLAGS) $< -o $@
$(EXE): $(EXE_OBJ)
	$(LINK) $+ $(LINKFLAGS) $(LINK_PTHREAD) -o $@

strip-debug: $(EXE).debug
%.debug: %
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@

clean:
	rm -v $(EXE) $(EXE_OBJ)

app:
	mkdir -p $(APP_DIR)
	cp -ru $(EXE) \
		$(NETMILL)/content-types.conf \
		$(NETMILL)/README.md \
		$(NETMILL)/LICENSE \
		$(NETMILL)/www \
		$(APP_DIR)
ifneq "$(LIBS3)" ""
	cp -ru $(LIBS3) \
		$(APP_DIR)
endif
ifeq "$(OS)" "windows"
	mv $(APP_DIR)/README.md $(APP_DIR)/README.txt
	unix2dos $(APP_DIR)/README.txt
endif


PKG_VER := test
PKG_ARCH := $(CPU)
PKG_PACKER := tar -c --owner=0 --group=0 --numeric-owner -v --zstd -f
PKG_EXT := tar.zst
ifeq "$(OS)" "windows"
	PKG_PACKER := zip -r -v
	PKG_EXT := zip
endif
PKG_NAME := netmill-$(PKG_VER)-$(OS)-$(PKG_ARCH).$(PKG_EXT)
package: $(PKG_NAME)
$(PKG_NAME): $(APP_DIR)
	$(PKG_PACKER) $@ $<


docker:
	docker build -t netmill:latest .


%.o: $(NETMILL)/src/test/%.c
	$(C) $(CFLAGS) $< -o $@
test: test.o \
		oclient.o \
		client.o \
		server.o \
		proxy-filters.o \
		tcp-listener.o
	$(LINK) $+ $(LINKFLAGS) -o $@
