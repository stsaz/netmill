# netmill: HTTP server

MODS += http.$(SO)
HTSV_OBJ += \
	http-sv-mod.o \
	http-sv-server.o \
	http-sv-conn.o \
	http-sv-chain.o \
	http-sv-proxy.o

ifdef HTCL_OBJ
	HTSV_OBJ += http-sv-proxy-chain.o
endif

http-sv-%.o: $(NETMILL)/src/http-server/%.c
	$(C) $(CFLAGS) $< -o $@

http.$(SO): $(HTSV_OBJ) $(HTCL_OBJ)
	$(LINK) -shared $+ $(LINKFLAGS) $(LINK_PTHREAD) -o $@
