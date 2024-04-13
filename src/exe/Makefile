# netmill executor

%.o: $(NETMILL)/src/exe/%.c
	$(C) $(CFLAGS) $< -o $@

$(EXE): main.o \
		core.$(SO)
	$(LINK) $+ $(LINKFLAGS) $(LINK_RPATH_ORIGIN) $(LINK_PTHREAD) $(LINK_DL) -o $@
