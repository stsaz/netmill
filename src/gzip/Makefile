# netmill: gzip module

MODS += gzip.$(SO)
FFPACK := $(ROOT_DIR)/ffpack
BINDIR := _$(OS)-$(CPU)
LIBS3 += $(FFPACK)/$(BINDIR)/libz-ffpack.$(SO)

%.o: $(NETMILL)/src/gzip/%.c
	$(C) $(CFLAGS) -I$(FFPACK) $< -o $@

gzip.$(SO): gzip.o
	$(LINK) -shared $+ $(LINKFLAGS) $(LINK_RPATH_ORIGIN) -L$(FFPACK)/$(BINDIR) -lz-ffpack -o $@
