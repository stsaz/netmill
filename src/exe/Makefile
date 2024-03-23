# netmill executor

exe-%.o: $(NETMILL)/src/exe/%.c
	$(C) $(CFLAGS) $< -o $@

%.o: $(NETMILL)/src/%.c
	$(C) $(CFLAGS) $< -o $@

$(EXE): exe-main.o nif.o \
		core.$(SO)
	$(LINK) $+ $(LINKFLAGS) $(LINK_RPATH_ORIGIN) $(LINK_PTHREAD) -o $@
