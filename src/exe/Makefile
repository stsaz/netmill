
EXE_OBJ += \
	exe-main.o \
	exe-cert.o \
	exe-dns.o \
	exe-http.o \
	exe-url.o

exe-%.o: $(NETMILL)/src/exe/%.c
	$(C) $(CFLAGS) $< -o $@

$(EXE): $(EXE_OBJ)
	$(LINK) $+ $(LINKFLAGS) $(LINK_PTHREAD) -o $@
