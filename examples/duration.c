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

struct data{
    uint32_t sec;
    uint32_t nsec;
    uint32_t addr1;
    uint32_t addr2;
    uint32_t type;
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};
uint64_t prog(struct packet *pkt)
{
    // check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) { 
        struct ip *ipv4 = (struct ip*)(((uint8_t *)&pkt->eth) + ETH_HLEN);
	struct data dt;
        uint32_t *p_src = &ipv4->ip_src.s_addr;
        uint32_t *p_dst = &ipv4->ip_dst.s_addr;
        uint32_t value = 0; // it is not really used

	// must be (smaller, greater)
        struct flowtuple pkey;
        if ((*p_src) < (*p_dst)) {
	    dt.addr1 = (*p_src);
            dt.addr2 = (*p_dst);
        } else {
	    dt.addr1 = (*p_dst);
            dt.addr2 = (*p_src);
        }        
        

        // Check if the ip packet contains a TCP payload
        if (ipv4->ip_p == 6) {
            struct tcphdr *tcp = (struct tcphdr *)(((uint32_t *)ipv4) + ipv4->ip_hl);

            if (tcp->th_flags & (TH_SYN | TH_FIN)) {
                struct data dt;
                if (tcp->th_flags & TH_SYN) {
		    dt.sec = pkt->metadata.sec;
                    dt.nsec = pkt->metadata.nsec;
		    dt.type = 0;
		    bpf_notify(0, &dt, sizeof(struct data));
                }

                else if (tcp->th_flags & TH_FIN) {
		    dt.sec = pkt->metadata.sec;
                    dt.nsec = pkt->metadata.nsec;
                    dt.type = 1;
		    bpf_notify(0, &dt, sizeof(struct data));
                }

                else if (tcp->th_flags & TH_RST) {
                    dt.sec = pkt->metadata.sec;
                    dt.nsec = pkt->metadata.nsec;
		    dt.type = 2;
		    bpf_notify(0, &dt, sizeof(struct data));
                }
            }
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
