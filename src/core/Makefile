# netmill core

%.o: $(NETMILL)/src/core/%.c
	$(C) $(CFLAGS) $< -o $@

core.$(SO): core.o \
		cache.o \
		tcp-listener.o \
		udp-listener.o \
		worker.o
	$(LINK) -shared $+ $(LINKFLAGS) -o $@
