# netmill: HTTP client

EXE_OBJ += \
	http-cl-client.o \
	http-cl-components.o
NML_HTTP_CLIENT := 1

http-cl-%.o: $(NETMILL)/src/http-client/%.c
	$(C) $(CFLAGS) $< -o $@
