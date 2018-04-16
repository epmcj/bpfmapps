#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

struct tstamp {
    uint32_t sec;
    uint32_t nsec;
};

struct flowtuple {
    uint32_t addr1;
    uint32_t addr2;
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flowtuple),
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") first_time = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flowtuple),
    .value_size = sizeof(struct tstamp),
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    // check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) {
        struct ip *ipv4 = (struct ip*)(((uint8_t *)&pkt->eth) + ETH_HLEN);
        uint32_t *p_src = &ipv4->ip_src.s_addr;
        uint32_t *p_dst = &ipv4->ip_dst.s_addr;
        
        // must be (smaller, greater)
        struct flowtuple pkey;
        if ((*p_src) < (*p_dst)) {
            pkey.addr1 = (*p_src);
            pkey.addr2 = (*p_dst);
        } else {
            pkey.addr1 = (*p_dst);
            pkey.addr2 = (*p_src);
        }

        // register new packet for the flow.
        uint32_t *value;
        uint32_t newvalue;
        if (bpf_map_lookup_elem(&counters, &pkey, &value) == -1)
            newvalue = 1;
        else
            newvalue = (*value) + 1;
        bpf_map_update_elem(&counters, &pkey, &newvalue, 0);

        // check if the flow was registered and register it if necessary.
        struct tstamp ftime;
        if (bpf_map_lookup_elem(&first_time, &pkey, &ftime) == -1) {
            ftime.sec  = pkt->metadata.sec;
            ftime.nsec = pkt->metadata.nsec;
            bpf_map_update_elem(&first_time, &pkey, &ftime, 0);
            bpf_notify(1, &ftime, sizeof(struct tstamp));
        }
    }

    /** Learning switch **/
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
                                                   
