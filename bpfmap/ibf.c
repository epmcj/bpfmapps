#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "ibf.h"
#include "lookuphash/lookup3.h"

typedef uint8_t counter_t; 

struct bpf_ibf {
    struct bpf_map      map;
    char*         ibf_array;
    char*      backup_array;
    uint16_t       n_hashes;
    uint16_t      n_buckets;
    uint8_t*       initvals;
    size_t        elem_size;
};

void xor(void *dst, void *src, int len) {
    int i;
    char *x1, *x2;
    x1 = (char*) dst;
    x2 = (char*) src;
    for (i = 0; i < len; i++) {
        (*x1) ^= (*x2);
        x1++; x2++;
    }
}

// FOR DEBUG !!
void print_key(void*key, uint32_t key_size){
    int i;
    char* kref = (char*) key;
    for (i = 0; i < key_size; i++) {
        printf("%02x", kref[i]);
    }
}

/** value_size must be equals to 4 (bytes) because we suppose the use of 
 ** uint32_t counters.
 */
struct bpf_map *ibf_map_alloc(union bpf_attr *attr) {
    struct bpf_ibf *ibftab;
    int err, i;

    if (attr->map_flags & ~BPF_F_NO_PREALLOC) {
        /* reserved bits should not be used */
        errno = EINVAL;
        return NULL;
    }

    ibftab = calloc(1, sizeof(*ibftab));
    if (!ibftab) {
        errno = ENOMEM;
        return NULL;
    }

    ibftab->n_buckets = (uint16_t)(attr->max_entries & 0x0000FFFF);
    ibftab->n_hashes  = (uint16_t)(attr->max_entries >> 16);
    
    /* mandatory map attributes */
    ibftab->map.map_type    = attr->map_type;
    ibftab->map.key_size    = attr->key_size;
    ibftab->map.max_entries = ibftab->n_buckets;
    ibftab->map.map_flags   = attr->map_flags;

    //printf("ibf: %d hashes and %d buckets\n", ibftab->n_hashes, 
    //                                            ibftab->n_buckets);
    /* check sanity of attributes. */
    if (ibftab->n_hashes == 0 || ibftab->n_buckets == 0 || 
        ibftab->map.key_size == 0) {
        goto free_ibftab;
    }

    /* creating table. */
    //ibftab->elem_size = sizeof(counter_t) + round_up(attr->key_size, 8);
    ibftab->elem_size = sizeof(counter_t) + attr->key_size;    
    //printf("elm_size:%ld\n", ibftab->elem_size);
    ibftab->ibf_array = calloc(ibftab->n_buckets, ibftab->elem_size);
    if (!ibftab->ibf_array) {
        goto free_ibftab;
    }

    /* generating hash init values !! NEEDS TO GUARANTEE DIFFERENT VALUES !! */
    ibftab->initvals = malloc(ibftab->n_hashes * sizeof(uint32_t));
    if (!ibftab->initvals) {
        goto free_ibftab;
    }

    for (i = 0; i < ibftab->n_hashes; i++) {
        ibftab->initvals[i] = rand();
    }

    return &ibftab->map;

free_ibftab:
    free(ibftab);
    errno = EINVAL;
    return NULL;
}

// query in count-min sketch
void *ibf_map_lookup_elem(struct bpf_map *map, void *key) {
    struct bpf_ibf *ibftab = container_of(map, struct bpf_ibf, map);
    uint16_t i, pos;
    counter_t *count;
    char *p;
    //printf("looking: ");
    //print_key(key, ibftab->map.key_size);
    /* finds min value of the entries in the tables */
    for (i = 1; i < ibftab->n_hashes; i++) {
        pos = hashlittle(key, ibftab->map.key_size, ibftab->initvals[i]);
        pos = pos % ibftab->n_buckets;
        //printf(" (%d:%d) ", i, pos);
        p = (char *) (ibftab->ibf_array + (pos * ibftab->elem_size));
        count = (counter_t *) p;
        if (*count == 0) {
            /* element not in set */
            //printf(" not in set\n");
            return NULL;
        } else if (*count == 1) {
            /* checking for key */
            p += sizeof(counter_t);
            if (memcmp(key, p, ibftab->map.key_size) == 0) {
                /* found the element */
                //printf(" found in set\n");
                return (void *) p;
            }
        }
    }
    //printf(" collision detected\n");
    return (void *) p;
}

/** insert the element in IBF. 
 ** for each hash: updates the counter + XOR the key + XOR the value
 ** parameter value is ignored
 */
int ibf_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags) {
    struct bpf_ibf *ibftab = container_of(map, struct bpf_ibf, map);
    uint16_t i, pos;
    counter_t *count;
    char *p;
//printf("updating: ");
//print_key(key, ibftab->map.key_size);
//printf("\n");
    for (i = 0; i < ibftab->n_hashes; i++) {
        pos = hashlittle(key, ibftab->map.key_size, ibftab->initvals[i]);
        pos = pos % ibftab->n_buckets;
        p = (char *) (ibftab->ibf_array + (pos * ibftab->elem_size));
        count = (counter_t *) p;
        (*count)++;
        p += sizeof(counter_t);
        /* storing <key> */
        xor(p, key, ibftab->map.key_size);
    }
    return 0;
}

//
int ibf_map_delete_elem(struct bpf_map *map, void *key) {
    struct bpf_ibf *ibftab = container_of(map, struct bpf_ibf, map);
    uint16_t i, pos;
    counter_t *count;
    char *p;
//printf("deleting <%d>\n", *((uint32_t *)key));
    for (i = 0; i < ibftab->n_hashes; i++) {
        pos = hashlittle(key, ibftab->map.key_size, ibftab->initvals[i]);
        pos = pos % ibftab->n_buckets;
        p = (char *) (ibftab->ibf_array + (pos * ibftab->elem_size));
        count = (counter_t *) p;
        /* checking if the key was previously inserted */
        if ((*count) == 0) {
            errno = EINVAL;
            return -1;
        }
        (*count)--;
        p += sizeof(counter_t);
        /* removing key */
        xor(p, key, ibftab->map.key_size);
    }
    return 0;
}

void ibf_map_free(struct bpf_map *map) {
    struct bpf_ibf *ibftab = container_of(map, struct bpf_ibf, map);
    free(ibftab->ibf_array);
    free(ibftab);
}

/* function used to list all or almost all ibf keys */
int ibf_map_get_next_key(struct bpf_map *map, void *key, void *last_key) {
    struct bpf_ibf *ibftab = container_of(map, struct bpf_ibf, map);
    uint32_t i, array_size;
    counter_t *count;
    char *p;
    /* starting to get the list */
    if (last_key == NULL) {
        /* create a copy of the array to get the keys */
        array_size = ibftab->n_buckets * ibftab->elem_size;
        ibftab->backup_array = malloc(array_size);
        if (!ibftab->backup_array) {
            errno = ENOMEM;
            return 0;
        }
        memcpy(ibftab->backup_array, ibftab->ibf_array, array_size);
    }
    
    for (i = 0; i < ibftab->n_buckets; i++) {
        p = (char *) (ibftab->ibf_array + (i * ibftab->elem_size));
        count = (counter_t *) p;
        if ((*count) == 1) {
            /* storing <key> */
            p += sizeof(counter_t);
            memcpy(key, p, map->key_size);
            ibf_map_delete_elem(map, key);
            return 0;
        }
    }
    
    /* can not get more keys */
    free(ibftab->ibf_array);
    ibftab->ibf_array = ibftab->backup_array;
    
    return -1;
}
