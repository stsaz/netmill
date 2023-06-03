# netmill Makefile

ROOT_DIR := ..
NETMILL := $(ROOT_DIR)/netmill
FFBASE := $(ROOT_DIR)/ffbase
FFOS := $(ROOT_DIR)/ffos

include $(FFBASE)/test/makeconf

EXE := netmill
APP_DIR := netmill-0
ifeq "$(OS)" "windows"
	EXE := netmill.exe
endif


CFLAGS := -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
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
	CFLAGS += -fsanitize=address
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
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) strip-debug
endif
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) app

$(EXE): main.o \
		server.o \
		client.o \
		filters.o \
		proxy.o \
		proxy-filters.o \
		tcp-listener.o \
		oclient.o
	$(LINK) $+ $(LINKFLAGS) $(LINK_PTHREAD) -o $@

DEPS := $(NETMILL)/Makefile $(NETMILL)/src/netmill.h \
	$(NETMILL)/src/util/*.h \
	$(FFOS)/FFOS/*.h \
	$(FFBASE)/ffbase/*.h

main.o: $(NETMILL)/src/main.c $(DEPS) \
		$(NETMILL)/src/*.h
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@

proxy-filters.o: $(NETMILL)/src/http-server/proxy-filters.c $(DEPS) \
		$(NETMILL)/src/http-server/proxy-data.h \
		$(NETMILL)/src/http-client/*.h
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/http-server/%.c $(DEPS) \
		$(NETMILL)/src/http-server/*.h
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/http-client/%.c $(DEPS) \
		$(NETMILL)/src/http-client/*.h
	$(C) $(CFLAGS) $< -o $@


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
	cp -ruv $(EXE) \
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
