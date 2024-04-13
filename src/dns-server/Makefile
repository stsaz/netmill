# netmill: DNS server

MODS += dns.$(SO)

DNSSRV_OBJ += \
	dns-mod.o \
	dns-conn.o \
	dns-chain.o \
	dns-server.o

DNSSRV_OBJ += \
	dns-upstream-doh-chain.o \
	3pt-base64.o

dns-%.o: $(NETMILL)/src/dns-server/%.c
	$(C) $(CFLAGS) -I$(NETMILL)/3pt $< -o $@

3pt-%.o: $(NETMILL)/3pt/%.c
	$(C) $(CFLAGS) $< -o $@

dns.$(SO): $(DNSSRV_OBJ)
	$(LINK) -shared $+ $(LINKFLAGS) -o $@
