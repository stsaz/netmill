# netmill Makefile

ROOT_DIR := ..
NETMILL := $(ROOT_DIR)/netmill
FFBASE := $(ROOT_DIR)/ffbase
FFOS := $(ROOT_DIR)/ffos

include $(FFBASE)/test/makeconf

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
CFLAGS += -I $(NETMILL)/src -I $(FFOS) -I $(FFBASE)
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

DEPS := $(NETMILL)/Makefile \
	$(NETMILL)/src/netmill.h \
	$(NETMILL)/src/util/*.h \
	$(FFOS)/FFOS/*.h \
	$(FFBASE)/ffbase/*.h

DNS_SRV_OBJ := \
	dns-client.o \
	dns-filters.o \
	dns-server.o
dns-%.o: $(NETMILL)/src/dns-server/%.c $(DEPS) \
		$(NETMILL)/src/dns-server/*.h
	$(C) $(CFLAGS) $< -o $@

HTTP_SRV_OBJ := \
	http-server.o \
	http-client.o \
	http-filters.o \
	http-proxy.o \
	http-proxy-filters.o
http-%.o: $(NETMILL)/src/http-server/%.c $(DEPS) \
		$(NETMILL)/src/http-server/*.h
	$(C) $(CFLAGS) $< -o $@
http-proxy-filters.o: $(NETMILL)/src/http-server/proxy-filters.c $(DEPS) \
		$(NETMILL)/src/http-server/proxy-data.h \
		$(NETMILL)/src/http-client/*.h
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/http-client/%.c $(DEPS) \
		$(NETMILL)/src/http-client/*.h
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/exe/%.c $(DEPS) \
		$(NETMILL)/src/exe/*.h
	$(C) $(CFLAGS) $< -o $@
$(EXE): main.o \
		tcp-listener.o udp-listener.o \
		oclient.o \
		nif.o \
		$(HTTP_SRV_OBJ) \
		$(DNS_SRV_OBJ)
	$(LINK) $+ $(LINKFLAGS) $(LINK_PTHREAD) -o $@


strip-debug: $(EXE).debug
%.debug: %
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@

clean:
	rm -fv $(EXE) *.o

app:
	mkdir -p $(APP_DIR)
	cp -ru $(EXE) \
		$(NETMILL)/content-types.conf \
		$(NETMILL)/README.md \
		$(NETMILL)/LICENSE \
		$(NETMILL)/www \
		$(APP_DIR)
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


%.o: $(NETMILL)/src/test/%.c $(DEPS) \
		$(NETMILL)/src/test/*.h \
		$(NETMILL)/src/http-server/*.h \
		$(NETMILL)/src/http-client/*.h
	$(C) $(CFLAGS) $< -o $@
test: test.o \
		oclient.o \
		client.o \
		server.o \
		proxy-filters.o \
		tcp-listener.o
	$(LINK) $+ $(LINKFLAGS) -o $@
