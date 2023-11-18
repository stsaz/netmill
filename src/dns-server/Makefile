# netmill: DNS server

EXE_OBJ += \
	dns-client.o \
	dns-chain.o \
	dns-server.o

EXE_OBJ += \
	dns-upstream-doh-chain.o \
	3pt-base64.o

dns-%.o: $(NETMILL)/src/dns-server/%.c
	$(C) $(CFLAGS) -I$(NETMILL)/3pt $< -o $@
3pt-%.o: $(NETMILL)/3pt/%.c
	$(C) $(CFLAGS) $< -o $@
