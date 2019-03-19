#ifndef __EBPF_SC_ARRAYMAP_H
#define __EBPF_SC_ARRAYMAP_H

#include "bpfmap.h"

struct bpf_map *sc_array_map_alloc(union bpf_attr *attr);
void sc_array_map_free(struct bpf_map *map);
void *sc_array_map_lookup_elem(struct bpf_map *map, void *key);
int sc_array_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int sc_array_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int sc_array_map_delete_elem(struct bpf_map *map, void *key);

#endif
