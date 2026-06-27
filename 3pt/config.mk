# Base settings for Makefile-s

include ../../ffbase/conf.mk

NML_CF += -fpic -fvisibility=hidden
NML_CF += -O3
CFLAGS += $(NML_CF)
CXXFLAGS += $(NML_CF)

NML_LF := $(LINK_INSTALLNAME_LOADERPATH) -static-libgcc
NML_LF += -s
LINKFLAGS += $(NML_LF)
LINKXXFLAGS += $(NML_LF) -static-libstdc++

SYS := $(OS)
ifeq "$(SYS)" "android"
	include ../android/andk.mk
	CFLAGS := $(NML_CF) $(A_CFLAGS)
	CXXFLAGS := $(NML_CF) $(A_CFLAGS)
	LINKFLAGS := $(NML_LF) $(A_LINKFLAGS)
	LINKXXFLAGS := $(NML_LF) $(A_LINKFLAGS)
endif

CURL := curl -L
UNTAR_BZ2 := tar -x --no-same-owner -f
UNTAR_GZ := tar -x --no-same-owner -f
UNTAR_XZ := tar -x --no-same-owner -f
UNTAR_ZST := tar -x --zstd --no-same-owner -f
UNZIP := unzip
