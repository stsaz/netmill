# netmill: gzip module

MODS += gzip.$(SO)
FFPACK := $(ROOT_DIR)/ffpack
LIBS3 += $(FFPACK)/_$(OS)-$(CPU)/libz-ffpack.$(SO)

%.o: $(NETMILL)/src/gzip/%.c
	$(C) $(CFLAGS) -I$(FFPACK) $< -o $@

gzip.$(SO): gzip.o
	$(LINK) -shared $+ $(LINKFLAGS) $(LINK_RPATH_ORIGIN) -L$(FFPACK)/_$(OS)-$(CPU) -lz-ffpack -o $@
