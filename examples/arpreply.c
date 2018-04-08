#include <linux/if_ether.h>
#include <netinet/ip.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") iptomac = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t), // IP address
    .value_size = 6, // MAC address
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") narp = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t), // IP address
    .value_size = sizeof(uint32_t),
    .max_entries = 3,
};

uint64_t prog(void *pkt)
{
    struct metadatahdr *metadatahdr = pkt;
    struct ethhdr *eth = pkt + sizeof(struct metadatahdr);
    // Check if the ethernet frame contains an arp packet
    unsigned int key = 0;
    uint32_t *count;
    if (eth->h_proto == 0x0608) { // ARP packet
        //struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
        key = 0;
        bpf_map_lookup_elem(&narp, &key, &count);

    } else if (eth->h_proto == 0x0008) { // IP packet
	key = 1;
        bpf_map_lookup_elem(&narp, &key, &count);

    } else {
        key = 2;
        bpf_map_lookup_elem(&narp, &key, &count);
    }
    (*count)++;

    /* learning switch behaviour */
    uint32_t *out_port;
    // if the source is not a broadcast or multicast
    if ((eth->h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, eth->h_source, &metadatahdr->in_port, 0);
    }

    // Flood if the destination is broadcast or multicast
    if (eth->h_dest[0] & 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, eth->h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
char _license[] SEC("license") = "GPL";
