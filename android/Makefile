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

AVD := @Pixel_6_API_33
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
	$(MKDIR) obj-amd64 $(LIB_DIR_AMD64)
	$(SUBMAKE) CPU=amd64 A_API=26 $(LIB_DIR_AMD64)/libnetmill.so.debug

lib-arm64:
	$(MKDIR) obj-arm64 $(LIB_DIR_ARM64)
	$(SUBMAKE) CPU=arm64 A_API=26 $(LIB_DIR_ARM64)/libnetmill.so.debug

clean-lib:
	$(RM) obj-arm64 obj-amd64 $(LIB_DIR_AMD64) $(LIB_DIR_ARM64)

OBJ_DIR := obj-$(CPU)
LIB_DIR := $(LIB_DIR_AMD64)
ifeq "$(CPU)" "arm64"
	LIB_DIR := $(LIB_DIR_ARM64)
else ifeq "$(CPU)" "arm"
	LIB_DIR := $(LIB_DIR_ARM)
endif
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
CFLAGS += -DFFBASE_HAVE_FFERR_STR
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
		$(OBJ_DIR)/netmill-jni.o \
		$(OBJ_DIR)/server.o \
		$(OBJ_DIR)/client.o \
		$(OBJ_DIR)/oclient.o \
		$(OBJ_DIR)/filters.o \
		$(OBJ_DIR)/proxy.o \
		$(OBJ_DIR)/proxy-filters.o \
		$(OBJ_DIR)/tcp-listener.o \
		$(OBJ_DIR)/nif.o
	$(LINK) -shared $(LINKFLAGS) $+ -o $@

DEPS := \
	$(wildcard $(NML_DIR)/src/*.h) \
	$(wildcard $(NML_DIR)/src/http-server/*.h) \
	$(wildcard $(NML_DIR)/src/http-client/*.h) \
	$(wildcard $(NML_DIR)/src/jni/*.h)
$(OBJ_DIR)/%.o: $(NML_DIR)/src/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
$(OBJ_DIR)/%.o: $(NML_DIR)/src/http-server/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
$(OBJ_DIR)/%.o: $(NML_DIR)/src/http-client/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@
$(OBJ_DIR)/%.o: $(NML_DIR)/src/jni/%.c $(DEPS)
	$(C) $(CFLAGS) $< -o $@

OBJCOPY := $(C_DIR)/llvm-objcopy
STRIP := $(C_DIR)/llvm-strip
%.debug: %
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@
