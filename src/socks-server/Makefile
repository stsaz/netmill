# netmill: SOCKS server

MODS += socks.$(SO)
SCKS_OBJ += \
	socks-mod.o \
	socks-conn.o \
	socks-chain.o \
	socks-server.o

socks-%.o: $(NETMILL)/src/socks-server/%.c
	$(C) $(CFLAGS) $< -o $@

socks.$(SO): $(SCKS_OBJ)
	$(LINK) -shared $+ $(LINKFLAGS) $(LINK_PTHREAD) -o $@
