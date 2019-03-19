#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") numpckts = {
//    .type = BPF_MAP_TYPE_SC_ARRAY,
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(uint64_t),
    .max_entries = 1,
};

// number of packets per protocol
struct bpf_map_def SEC("maps") numppp = {
//    .type = BPF_MAP_TYPE_SC_ARRAY,
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(uint64_t),
    .max_entries = 4,
};

uint64_t prog(struct packet *pkt)
{
    // Check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);        

        // Updating counter
        uint64_t *num; 
        unsigned int index = 0;
        //bpf_map_lookup_elem(&numpckts, &index, &num);
        //(*num)++;
        
        if (ipv4->ip_p == 0x06) { // tcp
            index = 1;
        } else if (ipv4->ip_p == 0x11) { // udp
            index = 2;        
        } else if (ipv4->ip_p == 0x01) { // icmp
            index = 3;
        }
        
        bpf_map_lookup_elem(&numppp, &index, &num);
        (*num)++;        
    }


    /* learning switch behaviour */
    uint32_t *out_port;
    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood if the destination is broadcast or multicast
    if (pkt->eth.h_dest[0] & 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
char _license[] SEC("license") = "GPL";

