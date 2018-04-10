#include <stdlib.h>
#include <stdio.h>
#include "cmin_sketch.h"
#include <errno.h>

struct objvalue {
    int32_t count;
    int32_t size;
    int16_t test;
};

int main(int argc, char *argv[]) {
    printf("testing cmin_sketch\n");

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_CMIN_SKETCH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 20,
        .map_flags = 0,
    };

    struct bpf_map *map = cmin_map_alloc(&attr);

    if (map == NULL) {
        printf("Invalid parameters for creating the map\n");
        return EXIT_FAILURE;
    }

    printf("map created successfully\n");

    uint32_t key = 0xaabbccdd;
    uint32_t value = 1; // 0xdeadbeef;
    void *elem = NULL;

    /* Lookup for a non existing element */
    elem = cmin_map_lookup_elem(map, &key);
    if (elem != NULL) {
        printf("Error: found element that shouldn't exist\n");
    }

    /* Update on a new element */
    if (cmin_map_update_elem(map, &key, &value, 0) == -1) {
        printf("Error: unable to insert entry in the hastable\n");
    }

    /* Lookup for existing element */
    elem = cmin_map_lookup_elem(map, &key);
    if (elem == NULL) {
        printf("Error: unable to get element previously inserted\n");
    }

    if (*(uint32_t *)elem != value) {
        printf("Error: lookup value is not the same as inserted\n");
        printf("Got %x expected %x\n", *(uint32_t *)elem, value);
    }

    /* Update the element again */
    value = 2; // 0x11223344;
    if (cmin_map_update_elem(map, &key, &value, 0) == -1) {
        printf("Error: unable to update entry in the hastable\n");
    }

    if (*(uint32_t *)elem != value) {
        printf("Error: lookup value is not the same as update\n");
        printf("Got %x expected %x\n", *(uint32_t *)elem, value);
    }


    /* Insert a second item */
    uint32_t key2 = 0x12345678;
    uint32_t value2 = 1; // 0xbeefbeef;
    if (cmin_map_update_elem(map, &key2, &value2, 0) == -1) {
        printf("Error: unable to insert entry in the hastable\n");
    }

    /* Lookup second item was inserted */
    elem = cmin_map_lookup_elem(map, &key2);
    if (elem == NULL) {
        printf("Error: unable to get element previously inserted\n");
    }

    if (*(uint32_t *)elem != value2) {
        printf("Error: lookup value is not the same as inserted\n");
        printf("Got %x expected %x\n", *(uint32_t *)elem, value2);
    }    

    return EXIT_SUCCESS;
}
