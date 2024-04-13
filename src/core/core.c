/** netmill: core
2024, Simon Zolin */

#include <netmill.h>
#include <util/util.h>
#include <ffsys/globals.h>

static void core_init(const nml_exe *x)
{
}

static void core_destroy()
{
}

extern const struct nml_udp_listener_if nml_udp_listener_interface;
extern const struct nml_tcp_listener_if nml_tcp_listener_interface;
extern const struct nml_worker_if nml_worker_interface;
extern const struct nml_cache_if nml_cache_interface;

static const void* core_provide(const char *name)
{
	static const struct nml_if_map map[] = {
		{"cache",			&nml_cache_interface},
		{"tcp_listener",	&nml_tcp_listener_interface},
		{"udp_listener",	&nml_udp_listener_interface},
		{"worker",			&nml_worker_interface},
	};
	return nml_if_map_find(map, FF_COUNT(map), name);
}

NML_MOD_DEFINE(core);
