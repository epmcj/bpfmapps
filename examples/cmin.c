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

struct bpf_map_def SEC("maps") cms = {
    .type = BPF_MAP_TYPE_CMIN_SKETCH,
    .key_size = sizeof(struct flowtuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = (7 << 16) | 6500,
};

struct bpf_map_def SEC("maps") max = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t), 
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") firsts = {
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
        uint32_t value = 0; // it is not really used

	// must be (smaller, greater)
        struct flowtuple pkey;
        if ((*p_src) < (*p_dst)) {
	    pkey.addr1 = (*p_src);
            pkey.addr2 = (*p_dst);
        } else {
	    pkey.addr1 = (*p_dst);
            pkey.addr2 = (*p_src);
        }

       // register new ip packet to p_src p_dst
        bpf_map_update_elem(&cms, &pkey, &value, 0);

        // get number of ip packets
        uint32_t *num_p;
        bpf_map_lookup_elem(&cms, &pkey, &num_p);

        // get the first time that p_dst received some ip packet or register
        // the packet time
        struct tstamp ftime, difftime;
        if (bpf_map_lookup_elem(&firsts, &pkey, &ftime) == -1) {
            ftime.sec  = pkt->metadata.sec;
            ftime.nsec = pkt->metadata.nsec;
            bpf_map_update_elem(&firsts, &pkey, &ftime, 0);

            difftime.sec  = 0;
            difftime.nsec = 0;
        } else {
            difftime.sec  = pkt->metadata.sec  - ftime.sec;
            difftime.nsec = pkt->metadata.nsec - ftime.nsec;

            if (difftime.sec == 0) // avoid division by zero
                difftime.sec = 1;

            // get the maximum number of packets per second allowed
            uint32_t *max_pkts;
            uint32_t key = 0;
            bpf_map_lookup_elem(&max, &key, &max_pkts);
            //bpf_notify(1, max_pkts, sizeof(uint32_t));
            uint32_t pkts_sec = ((*num_p) / difftime.sec);
            if (pkts_sec > (*max_pkts))
                bpf_notify(1, &pkey, sizeof(struct flowtuple));
            else
                bpf_notify(1, &pkts_sec, sizeof(uint32_t));
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
