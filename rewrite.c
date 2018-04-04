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

struct bpf_map_def SEC("maps") rwtable = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC addr
    .value_size = sizeof(uint32_t), // IP addr
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    // Check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) { // 0x0008 == ETH_P_PPP_MP
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	//uint32_t *src_addr = ipv4->ip_src.s_addr;
	//ipv4->ip_src.s_addr = 20481; // changing src address to 10.0.0.1.

	//uint32_t rw_addr;
	//bpf_map_lookup_elem(&rwtable, &src_addr, &rw_addr);        
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
