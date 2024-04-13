# netmill: HTTP client

HTCL_OBJ := \
	http-cl-url.o \
	http-cl-client.o \
	http-cl-components.o

http-cl-%.o: $(NETMILL)/src/http-client/%.c
	$(C) $(CFLAGS) $< -o $@
