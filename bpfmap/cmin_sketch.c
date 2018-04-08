#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "libghthash/ght_hash_table.h"
#include "bpfmap.h"

/* MUST SOLVE PROBLEM WITH KEY_SIZE (necessary)
   key_size = number of rows
   max_entries = number of columns
 */

#define MAX_VALUE UINT32_MAX
#define ELEM_SIZE (sizeof(uint32_t) << 3) // in bytes

typedef uint32_t cmin_elem;

struct bpf_cmintab {
    struct bpf_map map;
    void *elems;

    ght_hash_table_t** cmintab;
    ght_iterator_t iterator;
    cmin_elem *current;

    uint32_t num_rows;
    uint32_t num_columns;

    uint32_t n_buckets;
    uint32_t elem_size;
}

struct bpf_map *cmin_map_alloc(union bpf_attr *attr) {
    struct bpf_cmintab *cmintab;
    int err, i;
    uint64_t cost;

    if (attr->map_flags & ~BPF_F_NO_PREALLOC) {
        /* reserved bits should not be used */
        errno = EINVAL;
        return NULL;
    }

    cmintab = calloc(1, sizeof(*cmintab));
    if (!cmintab) {
        errno = ENOMEM;
        return NULL;
    }

    /* mandatory map attributes */
    cmintab->map.map_type = attr->map_type;
    cmintab->map.key_size = sizeof(uint32_t);//attr->key_size;
    cmintab->map.value_size = attr->value_size;
    cmintab->map.max_entries = attr->max_entries;
    cmintab->map.map_flags = attr->map_flags;

    /* check sanity of attributes. */
    if (cmintab->map.max_entries == 0 || cmintab->map.key_size == 0 ||
        cmintab->map.value_size == 0)
        goto free_cmintab;

    cmintab->num_rows    = attr->key_size;
    cmintab->num_columns = attr->max_entries;

    cmintab->cmintab = calloc(cmintab->num_rows, sizeof(ght_hash_table_t*));
    if (!cmintab->cmintab)
        goto free_cmintab;

    for (i = 0; i < cmintab->num_rows; i++) {   
        cmintab->cmintab[i] = ght_create(cmintab->num_columns);
        if (!cmintab->cmintab[i]) 
            goto free_cmintab;
    }

    cmintab->elem_size = sizeof(cmin_elem);

    return &cmintab->map;

free_htab:
    free(cmintab);
    errno = EINVAL;
    return NULL;
}

// query in count-min sketch
void *cmin_map_lookup_elem(struct bpf_map *map, void *key) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i;
    cmin_elem *e, *min;

    min = calloc(1, sizeof(cmin_elem));
    if (!min) {
        errno = EINVAL;
        return NULL;
    }
    (*min) = MAX_VALUE;

    /* finds min value of the entries in the tables */
    for (i = 0; i < cmintab->num_rows; i++) {
        e = ght_get(cmintab->cmintab[i], ELEM_SIZE, key); 
        if (!e) {
            errno = ENOENT;
            return NULL;
        }
        if ((*e) < (*min))
            memcpy(min, e, ELM_SIZE);
    }

    return min;
}

// update in count-min sketch
int cmin_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i, err;
    cmin_elem *old, *new;

    // updating each row entry
    for (i = 0; i < cmintab->num_rows; i++) {
        // ght_replace doesn't work
        old = ght_get(cmintab->cmintab[i], ELEM_SIZE, key);

        // Allocate the new element
        new = calloc(1, sizeof(cmin_elem));
        if (!new) {
            errno = ENOMEM;
            return -1;
        }

        if (old) { 
            memcpy(new, old, ELEM_SIZE);
            ght_remove(cmintab->cmintab, ELEM_SIZE, key);
            free(old);
        }
        (*new)++;

        err = ght_insert(cmintab->cmintab[i], new, ELM_SIZE, new); // might be a problem
        if (err)
            return err; 
    }

    return 0;
}

int cmin_map_delete_elem(struct bpf_map *map, void *key) {

}

void cmin_map_free(struct bpf_map *map) {

}

int cmin_map_get_next_key(struct bpf_map *map, void *key, void *next_key) {

}
