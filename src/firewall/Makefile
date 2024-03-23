# netmill: firewall

MODS += firewall.$(SO) nmlfw-xdp-ebpf.o
LIBXDP := $(NETMILL)/3pt/xdp-tools

CFLAGS_BPF := -c -S -g \
	-I$(NETMILL)/src \
	-Wall -Wextra \
	-O2 -emit-llvm

nmlfw-xdp-ebpf.o: $(NETMILL)/src/firewall/fw-xdp-ebpf.c
	clang $(CFLAGS_BPF) $< -o fw-xdp-ebpf.llvm
	llc -march=bpf -filetype=obj fw-xdp-ebpf.llvm -o $@

%.o: $(NETMILL)/src/firewall/%.c
	$(C) $(CFLAGS) -I$(LIBXDP)/headers $< -o $@

firewall.$(SO): firewall.o \
		xdp-ping.o \
		$(NETMILL)/3pt/xdp-tools/lib/libxdp/libxdp.a
	$(LINK) -shared $+ $(LINKFLAGS) -lbpf -o $@
