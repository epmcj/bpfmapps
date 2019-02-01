#ifndef __EBPF_CMINSKETCH_H
#define __EBPF_CMINSKETCH_H

#include "bpfmap.h"

struct bpf_map *cmin_map_alloc(union bpf_attr *attr);
void *cmin_map_lookup_elem(struct bpf_map *map, void *key);
int cmin_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int cmin_map_delete_elem(struct bpf_map *map, void *key);
void cmin_map_free(struct bpf_map *map);
int cmin_map_get_next_key(struct bpf_map *map, void *key, void *next_key);

#endif
