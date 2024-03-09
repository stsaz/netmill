# netmill: firewall

LIBXDP := $(ROOT_DIR)/xdp-tools-master

EXE_OBJ += firewall.o
LINKFLAGS += -lbpf -L$(LIBXDP)/lib/libxdp -lxdp

CFLAGS_BPF := -c -S -g \
	-I$(NETMILL)/src \
	-Wall -Wextra \
	-O2 -emit-llvm

nmlfw-xdp-ebpf.o: $(NETMILL)/src/firewall/fw-xdp-ebpf.c
	clang $(CFLAGS_BPF) $< -o - \
		| llc -march=bpf -filetype=obj -o $@

%.o: $(NETMILL)/src/firewall/%.c
	$(C) $(CFLAGS) -I$(LIBXDP)/headers $< -o $@
