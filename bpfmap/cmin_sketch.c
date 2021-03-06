#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "cmin_sketch.h"
#include "bpfmap.h"

typedef uint32_t counter_t; 

struct cmin_elem {
    char key[0] __attribute__((aligned(8)));
};

struct bpf_cmintab {
    struct bpf_map map;
    // void *elems;

    counter_t** cmin_table;
    uint16_t num_rows;
    uint16_t num_columns;

    uint8_t* as;
    uint8_t* bs;

    uint32_t n_buckets;
    // uint32_t elem_size;
};


uint32_t hash(uint8_t a, uint8_t b, void* key, uint32_t key_size) {
    uint32_t hvalue = 0;
    uint32_t i;

    for (i = 0; i < key_size; i++) {
        hvalue += (uint32_t) (((uint8_t *)key)[i]);
        hvalue += (hvalue << a);
        hvalue ^= (hvalue >> b);
    }
    hvalue += (hvalue << (b - a));
    hvalue ^= (hvalue >> (a - b));
    hvalue += (hvalue << (a + b));
    return hvalue;
}

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
    cmintab->map.map_type    = attr->map_type;
    cmintab->map.key_size    = attr->key_size;
    cmintab->map.value_size  = attr->value_size;
    cmintab->map.max_entries = attr->max_entries;
    cmintab->map.map_flags   = attr->map_flags;

    cmintab->num_columns = (uint16_t)(attr->max_entries & 0x0000FFFF);
    cmintab->num_rows    = (uint16_t)(attr->max_entries >> 16);

printf("%d,%d\n",cmintab->map.value_size, sizeof(counter_t));
    
    /* check sanity of attributes. */
    if (cmintab->map.max_entries == 0 || cmintab->map.key_size == 0 ||
        cmintab->map.value_size != sizeof(counter_t) || 
        cmintab->num_rows == 0 || cmintab->num_rows == 0)
        goto free_cmintab;

    /* creating table. */
    cmintab->cmin_table = calloc(cmintab->num_rows, sizeof(counter_t*));
    if (!cmintab->cmin_table)
        goto free_cmintab;

    for (i = 0; i < cmintab->num_rows; i++) {   
        cmintab->cmin_table[i] = calloc(cmintab->num_columns, sizeof(counter_t));
        if (!cmintab->cmin_table[i]) {
            goto free_cmintab;
        }
    }

    /* generating hash coefficients. */
    cmintab->as = calloc(cmintab->num_rows, sizeof(uint8_t));
    if (!cmintab->as) {
        goto free_cmintab;
    }
    cmintab->bs = calloc(cmintab->num_rows, sizeof(uint8_t));
    if (!cmintab->bs) {
        goto free_cmintab;
    }
    for (i = 0; i < cmintab->num_rows; i++) {
        cmintab->as[i] = rand();
        cmintab->bs[i] = rand();
    }

    // cmintab->elem_size = sizeof(struct cmin_elem) +
    //                      round_up(cmintab->map.key_size, 8) +
    //                      round_up(cmintab->map.value_size, 8);

    return &cmintab->map;

free_cmintab:
    free(cmintab);
    errno = EINVAL;
    return NULL;
}

// query in count-min sketch
void *cmin_map_lookup_elem(struct bpf_map *map, void *key) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i, col;
    // struct cmin_elem *e;
    counter_t *min, *curr;

    /* finds min value of the entries in the tables */
    col = hash(cmintab->as[0], cmintab->bs[0], key, cmintab->map.key_size);
    col = col % cmintab->num_columns;
    min = (counter_t *) (&cmintab->cmin_table[0][col]);
    for (i = 1; i < cmintab->num_rows; i++) {
        col = hash(cmintab->as[i], cmintab->bs[i], key, cmintab->map.key_size);
        col = col % cmintab->num_columns;
        curr = (counter_t *) (&cmintab->cmin_table[i][col]);
        if ((*curr) < (*min)) {
            min = curr;
        }
    }

    return min;
}

/** update in count-min sketch
 ** parameter value is ignored
 */
int cmin_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i, col;
    // counter_t *value;

    // updating each row entry (increasing counters)
    for (i = 0; i < cmintab->num_rows; i++) {
        col = hash(cmintab->as[i], cmintab->bs[i], key, cmintab->map.key_size);
        col = col % cmintab->num_columns;
        cmintab->cmin_table[i][col] = cmintab->cmin_table[i][col] + 1;
    }

    return 0;
}

// not necessary?
int cmin_map_delete_elem(struct bpf_map *map, void *key) {
    return -1;
}

void cmin_map_free(struct bpf_map *map) {
    struct bpf_cmintab *cmintab = container_of(map, struct bpf_cmintab, map);
    int i;

    for (i = 0; i < cmintab->num_rows; i++) {
        free(cmintab->cmin_table[i]);
    }
    free(cmintab->cmin_table);
    free(cmintab);
}

// not necessary
int cmin_map_get_next_key(struct bpf_map *map, void *key, void *next_key) {
    return -1;
}
