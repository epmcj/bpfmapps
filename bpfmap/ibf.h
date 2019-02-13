/* Invertible Bloom Filter implementation
 * References:
 * (1) "Invertible Bloom Lookup Tables" by Goodrich, M. and Mitzenmacher, M.
 * (2) The Invertible Bloom Filter by James, M. Available at:
 *     https://www.i-programmer.info/programming/theory/4641-the-invertible-bloom-filter.html 
 */

#ifndef __EBPF_ibf_H
#define __EBPF_ibf_H

#include "bpfmap.h"

struct bpf_map *ibf_map_alloc(union bpf_attr *attr);
void *ibf_map_lookup_elem(struct bpf_map *map, void *key);
int ibf_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int ibf_map_delete_elem(struct bpf_map *map, void *key);
void ibf_map_free(struct bpf_map *map);
int ibf_map_get_next_key(struct bpf_map *map, void *key, void *next_key);

#endif
