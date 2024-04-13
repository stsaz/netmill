# netmill: SSL module

MODS += ssl.$(SO)
CFLAGS_OPENSSL := $(CFLAGS) -Wno-deprecated-declarations \
	-I$(NETMILL)/3pt/openssl/openssl-3.1.3/include
SSL_LINKFLAGS := $(LINKFLAGS)
ifeq "$(OS)" "linux"
	SSL_LINKFLAGS += -L$(NETMILL)/3pt/_$(OS)-$(CPU) -lssl -lcrypto
else
	SSL_LINKFLAGS += -L$(NETMILL)/3pt/_$(OS)-$(CPU) -lssl-3-x64 -lcrypto-3-x64
	LIBS3 += \
		$(NETMILL)/3pt/_$(OS)-$(CPU)/libssl-3-x64.dll \
		$(NETMILL)/3pt/_$(OS)-$(CPU)/libcrypto-3-x64.dll
endif

ffssl.o: $(NETMILL)/src/util/ffssl.c
	$(C) $(CFLAGS_OPENSSL) $< -o $@

%.o: $(NETMILL)/src/ssl/%.c
	$(C) $(CFLAGS) $< -o $@

ssl.$(SO): ssl.o \
		cert.o \
		ffssl.o
	$(LINK) -shared $+ $(SSL_LINKFLAGS) -o $@
