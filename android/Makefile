# Android project makefile

# Undefine built-in rules, suffixes and variables
MAKEFLAGS += -Rr

# Set utils
SUBMAKE := $(MAKE) -f $(firstword $(MAKEFILE_LIST))
MKDIR := mkdir -p
RM := rm -rf
CP := cp -au
LS := ls -l

# SDK_DIR := /Android/Sdk
SDK_API := 33.0.0
NDK_VER := 25.1.8937393
NDK_DIR := $(SDK_DIR)/ndk/$(NDK_VER)
# ADB_FLAGS := -d

CPU := amd64
APK_ID := com.github.stsaz.netmill
APK := netmill/build/outputs/apk/release/netmill-release-unsigned.apk
ifeq "$(DEBUG)" "1"
	APK_ID := com.github.stsaz.netmill.debug
	APK := netmill/build/outputs/apk/debug/netmill-debug.apk
endif

build:
	$(MAKE) SDK_DIR=$(SDK_DIR) lib-arm64
	$(MAKE) SDK_DIR=$(SDK_DIR) build-java


# Build .apk

GRADLE := ./gradlew
GRADLE_BUILD := assembleRelease
ifeq "$(DEBUG)" "1"
	GRADLE_BUILD := assembleDebug
endif

build-java:
	$(GRADLE) $(GRADLE_BUILD)
	$(LS) $(APK)

clean-java:
	$(GRADLE) clean

apk-list:
	unzip -l $(APK)


# Sign .apk

APK_KEY_STORE :=
APK_KEY_PASS :=
APK_VER := test
APK_SIGNED := netmill-$(APK_VER)-android-$(CPU).apk

sign:
	$(SDK_DIR)/build-tools/$(SDK_API)/zipalign -v -f 4 $(APK) $(APK_SIGNED)
	$(SDK_DIR)/build-tools/$(SDK_API)/apksigner sign --ks $(APK_KEY_STORE) --ks-pass pass:$(APK_KEY_PASS) $(APK_SIGNED)
	$(SDK_DIR)/build-tools/$(SDK_API)/apksigner verify $(APK_SIGNED)

install-signed:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) install -r $(APK_SIGNED)


# Upload and install .apk on Android device

install:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) install -r $(APK)

uninstall:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) uninstall $(APK_ID)

build-install: build
	$(MAKE) install


# Show logs

log:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) logcat -v time | grep --color=auto --line-buffered '/netmill'

log-error:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) logcat -v time | grep -E --color=auto --line-buffered '/netmill|W/|E/'

log-clear:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) logcat -c

log-bt:
	$(SDK_DIR)/platform-tools/adb $(ADB_FLAGS) logcat -v time | $(NDK_DIR)/ndk-stack -sym netmill/libs/x86_64


# Start Android emulator

AVD :=
emulator:
	$(SDK_DIR)/emulator/emulator -list-avds
	$(SDK_DIR)/emulator/emulator $(AVD)


include andk.mk

# Directories
ROOT_DIR := ../..
NML_DIR := $(ROOT_DIR)/netmill
FFBASE_DIR := $(ROOT_DIR)/ffbase
FFSYS_DIR := $(ROOT_DIR)/ffsys

LIB_DIR_AMD64 := $(NML_DIR)/android/netmill/libs/x86_64
LIB_DIR_ARM64 := $(NML_DIR)/android/netmill/libs/arm64-v8a
LIB_DIR_ARM := $(NML_DIR)/android/netmill/libs/armeabi-v7a

lib-amd64:
	$(MKDIR) ../_android-amd64 $(LIB_DIR_AMD64)
	$(MAKE) libs \
		-C ../_android-amd64 \
		-f $(NML_DIR)/android/Makefile \
		-I $(NML_DIR)/android \
		CPU=amd64

lib-arm64:
	$(MKDIR) ../_android-arm64 $(LIB_DIR_ARM64)
	$(MAKE) libs \
		-C ../_android-arm64 \
		-f $(NML_DIR)/android/Makefile \
		-I $(NML_DIR)/android \
		CPU=arm64

libs: $(LIB_DIR_AMD64)/libnetmill.so.debug

clean-lib:
	$(RM) ../_android-arm64 ../_android-amd64 $(LIB_DIR_AMD64) $(LIB_DIR_ARM64)

LIB_DIR := $(LIB_DIR_AMD64)
ifeq "$(CPU)" "arm64"
	LIB_DIR := $(LIB_DIR_ARM64)
else ifeq "$(CPU)" "arm"
	LIB_DIR := $(LIB_DIR_ARM)
endif
CFLAGS += -std=c99
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-multichar
CFLAGS += -DNML_STATIC_LINKING -DFFBASE_HAVE_FFERR_STR
CFLAGS += -I $(NML_DIR)/src -I $(FFSYS_DIR) -I $(FFBASE_DIR)
ifeq "$(DEBUG)" "1"
	CFLAGS += -g
	CFLAGS += -DNML_ENABLE_LOG_EXTRA -DFF_DEBUG -O0
else
	CFLAGS += -O3 -fno-strict-aliasing
endif
LINKFLAGS += \
	-llog

$(LIB_DIR)/libnetmill.so: \
		netmill-jni.o \
		core-tcp-listener.o \
		http-sv-server.o \
		http-sv-client.o \
		http-sv-chain.o \
		http-sv-proxy.o \
		http-sv-proxy-chain.o \
		http-cl-client.o \
		http-cl-components.o \
		nif.o
	$(LINK) -shared $(LINKFLAGS) $+ -o $@

%.o: $(NML_DIR)/src/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
core-%.o: $(NML_DIR)/src/core/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
http-sv-%.o: $(NML_DIR)/src/http-server/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
http-cl-%.o: $(NML_DIR)/src/http-client/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
%.o: $(NML_DIR)/src/jni/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@

OBJCOPY := $(C_DIR)/llvm-objcopy
STRIP := $(C_DIR)/llvm-strip
%.debug: %
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@
