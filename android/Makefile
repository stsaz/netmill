# Android project makefile

# Undefine built-in rules, suffixes and variables
MAKEFLAGS += -Rr

# Set utils
SUBMAKE := +$(MAKE) -f $(firstword $(MAKEFILE_LIST))
MKDIR := mkdir -p
RM := rm -rf
CP := cp -au
LS := ls -l

ANDROID_HOME ?= /Android
SDK_API := 33.0.0
NDK_VER := 25.1.8937393
NDK_DIR := $(ANDROID_HOME)/ndk/$(NDK_VER)
# ADB_FLAGS := -d

CPU := amd64
LIB_DIR_CPU := x86_64
ifeq "$(CPU)" "arm64"
	LIB_DIR_CPU := arm64-v8a
else ifeq "$(CPU)" "arm"
	LIB_DIR_CPU := armeabi-v7a
endif
APK_ID := com.github.stsaz.netmill
APK := netmill/build/outputs/apk/release/netmill-release-unsigned.apk
ifeq "$(DEBUG)" "1"
	APK_ID := com.github.stsaz.netmill.debug
	APK := netmill/build/outputs/apk/debug/netmill-debug.apk
endif

default: libs
	$(SUBMAKE) apk


# Build .apk

GRADLE := ./gradlew
GRADLE_BUILD := assembleRelease
ifeq "$(DEBUG)" "1"
	GRADLE_BUILD := assembleDebug
endif

apk:
	cd $(NETMILL)/android && $(GRADLE) $(GRADLE_BUILD)

clean-java:
	cd $(NETMILL)/android && $(GRADLE) clean

apk-list:
	unzip -l $(APK)


# Sign .apk

APK_KEY_STORE :=
APK_KEY_PASS :=
APK_VER := test
APK_SIGNED := netmill-$(APK_VER)-android-$(CPU).apk

sign:
	cd $(NETMILL)/android && $(ANDROID_HOME)/build-tools/$(SDK_API)/zipalign -v -f 4 $(APK) $(APK_SIGNED)
	cd $(NETMILL)/android && $(ANDROID_HOME)/build-tools/$(SDK_API)/apksigner sign \
		--ks $(APK_KEY_STORE) \
		--ks-pass pass:$(APK_KEY_PASS) \
		$(APK_SIGNED)
	cd $(NETMILL)/android && $(ANDROID_HOME)/build-tools/$(SDK_API)/apksigner verify $(APK_SIGNED)

install-signed:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) install -r $(APK_SIGNED)


# Upload and install .apk on Android device

install:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) install -r $(APK)

uninstall:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) uninstall $(APK_ID)

build-install: apk
	$(SUBMAKE) install


# Show logs

log:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) logcat -v time | grep --color=auto --line-buffered '/netmill'

log-error:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) logcat -v time | grep -E --color=auto --line-buffered '/netmill|W/|E/'

log-clear:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) logcat -c

log-bt:
	$(ANDROID_HOME)/platform-tools/adb $(ADB_FLAGS) logcat -v time | $(NDK_DIR)/ndk-stack -sym netmill/libs/$(LIB_DIR_CPU)


include andk.mk

# Directories
ROOT_DIR := ../..
NETMILL := $(ROOT_DIR)/netmill
FFBASE_DIR := $(ROOT_DIR)/ffbase
FFSYS_DIR := $(ROOT_DIR)/ffsys

LIB_DIR_AMD64 := $(NETMILL)/android/netmill/libs/x86_64
LIB_DIR_ARM64 := $(NETMILL)/android/netmill/libs/arm64-v8a
LIB_DIR_ARM := $(NETMILL)/android/netmill/libs/armeabi-v7a
LIB_DIR := $(NETMILL)/android/netmill/libs/$(LIB_DIR_CPU)
ifeq "$(TARGETS)" ""
override TARGETS := $(LIB_DIR)/libnetmill.so
endif
libs:
	mkdir -p $(LIB_DIR)
	$(SUBMAKE) strip-debug

clean-lib:
	$(RM) ../_android-arm64 ../_android-amd64 $(LIB_DIR_AMD64) $(LIB_DIR_ARM64)

CFLAGS += -std=c11
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-multichar
CFLAGS += -DNML_STATIC_LINKING -DFFBASE_HAVE_FFERR_STR \
	-MMD -MP  \
	-I$(NETMILL)/src -I$(FFSYS_DIR) -I$(FFBASE_DIR) \
	-g
ifeq "$(DEBUG)" "1"
	CFLAGS += -DNML_ENABLE_LOG_EXTRA -DFF_DEBUG -O0 -Werror
else
	CFLAGS += -O3 -fno-strict-aliasing
endif
CFLAGS += $(CFLAGS_USER)
LINKFLAGS += \
	-llog

-include $(wildcard *.d)

include $(NETMILL)/src/core/Makefile
include $(NETMILL)/src/http-client/Makefile
include $(NETMILL)/src/http-server/Makefile

$(LIB_DIR)/libnetmill.so: \
		netmill-jni.o \
		tcp-listener.o \
		worker.o \
		cache.o \
		http-sv-server.o \
		http-sv-conn.o \
		http-sv-chain.o \
		http-sv-proxy.o \
		http-sv-proxy-chain.o \
		http-cl-client.o \
		http-cl-components.o \
		nif.o
	$(LINK) -shared $(LINKFLAGS) $+ -o $@

%.o: $(NETMILL)/src/%.c
	$(C) $(CFLAGS) $< -o $@
%.o: $(NETMILL)/src/jni/%.c
	$(C) $(CFLAGS) $< -o $@

OBJCOPY := $(C_DIR)/llvm-objcopy
STRIP := $(C_DIR)/llvm-strip
strip-debug: $(addsuffix .debug,$(TARGETS))
%.debug: %
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@

PKG_ARCH := $(CPU)
PKG_PACKER := tar -c --owner=0 --group=0 --numeric-owner -v --zstd -f
PKG_EXT := tar.zst
ifeq "$(OS)" "windows"
	PKG_PACKER := zip -r -v
	PKG_EXT := zip
endif

PKG_DEBUG_NAME := netmill-$(APK_VER)-android-$(PKG_ARCH)-debug.$(PKG_EXT)
$(PKG_DEBUG_NAME): $(wildcard $(NETMILL)/android/netmill/libs/$(LIB_DIR_CPU)/*.debug)
	cd $(NETMILL) && $(PKG_PACKER) $@ android/netmill/libs/$(LIB_DIR_CPU)/*.debug
package-debug: $(PKG_DEBUG_NAME)

release: default
	$(SUBMAKE) package-debug
	$(SUBMAKE) sign
