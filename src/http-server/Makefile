# netmill: HTTP server

EXE_OBJ += \
	http-sv-server.o \
	http-sv-client.o \
	http-sv-chain.o \
	http-sv-proxy.o

ifeq "$(NML_HTTP_CLIENT)" "1"
	EXE_OBJ += http-sv-proxy-chain.o
endif

http-sv-%.o: $(NETMILL)/src/http-server/%.c
	$(C) $(CFLAGS) $< -o $@
