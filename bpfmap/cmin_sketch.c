#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "libghthash/ght_hash_table.h"
#include "bpfmap.h"

typedef uint32_t counter_t; 

struct cmin_elem {
    char key[0] __attribute__((aligned(8)));
};

struct bpf_cmintab {
    struct bpf_map map;
    void *elems;

    ght_hash_table_t** cmintab;
    ght_iterator_t iterator;
    struct cmin_elem *current;

    uint16_t num_rows;
    uint16_t num_columns;

    uint32_t n_buckets;
    uint32_t elem_size;
};

/** value_size must be equals to 4 (bytes) because we suppose the use of 
 ** uint32_t counters.
 */
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
    cmintab->map.key_size = attr->key_size;
    cmintab->map.value_size = attr->value_size;
    cmintab->map.max_entries = attr->max_entries;
    cmintab->map.map_flags = attr->map_flags;

    cmintab->num_columns = (uint16_t)(attr->max_entries & 0x0000FFFF);
    cmintab->num_rows    = (uint16_t)(attr->max_entries >> 16);

    /* check sanity of attributes. */
    if (cmintab->map.max_entries == 0 || cmintab->map.key_size == 0 ||
        cmintab->map.value_size != sizeof(counter_t) || 
        cmintab->num_rows == 0 || cmintab->num_rows == 0)
        goto free_cmintab;


    cmintab->cmintab = calloc(cmintab->num_rows, sizeof(ght_hash_table_t*));
    if (!cmintab->cmintab)
        goto free_cmintab;

    for (i = 0; i < cmintab->num_rows; i++) {   
        cmintab->cmintab[i] = ght_create(cmintab->num_columns);
        if (!cmintab->cmintab[i]) 
            goto free_cmintab;
    }

    cmintab->elem_size = sizeof(struct cmin_elem) +
                         round_up(cmintab->map.key_size, 8) +
                         round_up(cmintab->map.value_size, 8);

    return &cmintab->map;

free_cmintab:
    free(cmintab);
    errno = EINVAL;
    return NULL;
}

// query in count-min sketch
void *cmin_map_lookup_elem(struct bpf_map *map, void *key) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i;
    struct cmin_elem *e;
    counter_t *min, *curr;

    /* finds min value of the entries in the tables */
    e = ght_get(cmintab->cmintab[0], map->key_size, key);
    min = (counter_t *) (e->key + round_up(map->key_size, 8));
    for (i = 1; i < cmintab->num_rows; i++) {
        e = ght_get(cmintab->cmintab[i], map->key_size, key); 
        if (!e) {
            errno = ENOENT;
            return NULL;
        }
        curr = (counter_t *) (e->key + round_up(map->key_size, 8));
        if ((*curr) < (*min))
            min = curr;
    }

    return min;
}

/** update in count-min sketch
 ** parameter value is ignored
 */
int cmin_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i, err;
    struct cmin_elem *e_old, *e_new;
    counter_t *old_val, *new_val;

    new_val = calloc(1, sizeof(counter_t));
    if (!new_val) {
        errno = ENOMEM;
        return -1;
    }

    // updating each row entry
    for (i = 0; i < cmintab->num_rows; i++) {
        // ght_replace doesn't work
        e_old = ght_get(cmintab->cmintab[i], map->key_size, key);
        if (e_old) {
            old_val = (counter_t *) (e_old->key + round_up(map->key_size, 8));
            memcpy(new_val, old_val, sizeof(counter_t));
            ght_remove(cmintab->cmintab, map->key_size, key);
            free(e_old);
        } else {

        }
        (*new_val) += 1;

        // Allocate the new element
        e_new = calloc(1, cmintab->elem_size);
        if (!e_new) {
            errno = ENOMEM;
            return -1;
        }

        memcpy(e_new->key, key, map->key_size);
        memcpy(e_new->key + round_up(map->key_size, 8), new_val, map->value_size);

        err = ght_insert(cmintab->cmintab[i], e_new->key, map->key_size, e_new);
        if (err)
            return err; 
    }

    return 0;
}

// not necessary?
int cmin_map_delete_elem(struct bpf_map *map, void *key) {
    return -1;
}

void cmin_map_free(struct bpf_map *map) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    ght_iterator_t iterator;
    const void *p_key;
    void *p_e;
    int i;

    for (i = 0; i < cmintab->num_rows; i++) {
        for (p_e = ght_first(cmintab->cmintab[i], &iterator, &p_key); p_e; p_e = ght_next(cmintab->cmintab[i], &iterator, &p_key)) {
            free(p_e);
        }
        ght_finalize(cmintab->cmintab[i]);
    }
    free(cmintab);
}

// not necessary
int cmin_map_get_next_key(struct bpf_map *map, void *key, void *next_key) {
    return -1;
}
