# netmill: DNS server

EXE_OBJ += \
	dns-client.o \
	dns-filters.o \
	dns-server.o

dns-%.o: $(NETMILL)/src/dns-server/%.c
	$(C) $(CFLAGS) $< -o $@
