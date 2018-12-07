#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") trafficmux = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 64,
};

uint64_t prog(void *pkt)
{
    struct metadatahdr *metadatahdr = pkt;
    struct ethhdr *eth = pkt + sizeof(struct metadatahdr);

    unsigned char *src = eth->h_source;

    uint32_t *item;
    uint32_t newitem=0;
    if (bpf_map_lookup_elem(&trafficmux, src, &item) == -1) { // No entry was found
        //item = &newitem;

        bpf_map_update_elem(&trafficmux, src, &newitem, 1);
    }
    else{
         newitem=*item;
         newitem++; 
         bpf_map_update_elem(&trafficmux, src, &newitem, 2);
    }

//forwarding
    if (metadatahdr->in_port == 0) {
        if (newitem & 1) return 2;
        return 1;
    }

    return 0;

}
char _license[] SEC("license") = "GPL";
