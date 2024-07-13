# netmill Makefile

ROOT_DIR := ..
NETMILL := $(ROOT_DIR)/netmill
FFBASE := $(ROOT_DIR)/ffbase
FFSYS := $(ROOT_DIR)/ffsys

include $(FFBASE)/conf.mk

EXE := netmill$(DOTEXE)
APP_DIR := netmill-0

CFLAGS := -std=c99
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-multichar
ifeq "$(COMPILER)" "gcc"
	CFLAGS += -Wno-nonnull -Wno-array-bounds -Wno-stringop-overflow
endif
CFLAGS += -DNML_STATIC_LINKING -DFFBASE_HAVE_FFERR_STR \
	-MMD -MP \
	-I$(NETMILL)/src -I$(FFSYS) -I$(FFBASE) \
	-fPIC \
	-g
ifeq "$(DEBUG)" "1"
	CFLAGS += -DNML_ENABLE_LOG_EXTRA -DFF_DEBUG -O0 -Werror
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
LINK_DL :=
ifeq "$(OS)" "linux"
	LINK_DL := -ldl
endif


default: build
ifneq "$(DEBUG)" "1"
	$(SUBMAKE) strip-debug
endif
	$(SUBMAKE) app

-include $(wildcard *.d)

include $(NETMILL)/src/core/Makefile
include $(NETMILL)/src/dns-server/Makefile
include $(NETMILL)/src/exe/Makefile
# include $(NETMILL)/src/firewall/Makefile
include $(NETMILL)/src/gzip/Makefile
include $(NETMILL)/src/http-client/Makefile
include $(NETMILL)/src/http-server/Makefile
include $(NETMILL)/src/ssl/Makefile


MODS += if.$(SO)
ifeq "$(OS)" "windows"
LINK_IPHELPAPI := -liphlpapi
endif

%.o: $(NETMILL)/src/%.c
	$(C) $(CFLAGS) $< -o $@

if.$(SO): nif.o
	$(LINK) -shared $+ $(LINKFLAGS) $(LINK_IPHELPAPI) -o $@


ifeq "$(TARGETS)" ""
override TARGETS := core.$(SO) $(EXE) $(MODS)
endif
build: $(TARGETS)

strip-debug: $(addsuffix .debug,$(TARGETS))
%.debug: %
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@

app:
	mkdir -p $(APP_DIR)
	cp -ru $(EXE) core.$(SO) \
		$(NETMILL)/content-types.conf \
		$(NETMILL)/README.md \
		$(NETMILL)/LICENSE \
		$(NETMILL)/www \
		$(APP_DIR)

	mkdir -p $(APP_DIR)/ops
	cp -ru $(MODS) \
		$(APP_DIR)/ops
ifneq "$(LIBS3)" ""
	cp -ru $(LIBS3) \
		$(APP_DIR)/ops
endif
	chmod 644 $(APP_DIR)/ops/*

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
$(PKG_NAME): $(APP_DIR)
	$(PKG_PACKER) $@ $<
package: $(PKG_NAME)

PKG_DEBUG_NAME := netmill-$(PKG_VER)-$(OS)-$(PKG_ARCH)-debug.$(PKG_EXT)
$(PKG_DEBUG_NAME):
	$(PKG_PACKER) $@ *.debug
package-debug: $(PKG_DEBUG_NAME)

release: default
	$(SUBMAKE) package
	$(SUBMAKE) package-debug


docker: $(APP_DIR)
	docker build -t netmill:latest .


%.o: $(NETMILL)/src/test/%.c
	$(C) $(CFLAGS) $< -o $@
test: test.o
	$(LINK) $+ $(LINKFLAGS) -o $@
