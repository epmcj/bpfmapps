#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

uint64_t prog(struct packet *pkt)
{
  if (pkt->metadata.in_port == 0) {

    // Check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008) {
      struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);

      // Check if the ip packet contains a TCP payload
      if (ipv4->ip_p == 6) {
        struct tcphdr *tcp = (struct tcphdr *)(((uint32_t *)ipv4) + ipv4->ip_hl);

        if (tcp->th_seq & 1){
          return 2;
        }
        return 1;
      }
    }
    return 1;
  }
  return 0;
  
}

char _license[] SEC("license") = "GPL";
