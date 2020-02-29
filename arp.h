#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>

#include "hacking.h"
#include "hacking-network.h"

struct arp_hdr {
   u_short hw_type;
   u_short proto_type;
   u_char hw_addr_len;
   u_char proto_addr_len;
   u_short operation;
   u_char src_hw_addr[ETHER_ADDR_LEN];
   u_char src_proto_addr[4];
   u_char target_hw_addr[ETHER_ADDR_LEN];
   u_char target_proto_addr[4];
};

void print_arp_packet(u_char *packet) {
      struct eth_hdr *eth = (struct eth_hdr*) packet;
      struct arp_hdr *arp = (struct arp_hdr*) (eth + 1);

      if (eth->ether_type != htons(ETH_P_ARP))
         return;
		
      printf("\nDestination MAC: ");
      printMac(eth->ether_dest_addr); printf("\n");
      printf("Source MAC: ");
      printMac(eth->ether_src_addr); printf("\n");

      printf("Hardware type: %#06x | length: %u\n", ntohs(arp->hw_type), arp->hw_addr_len);
      printf("Protocol type: %#06x | lenth: %u\n", ntohs(arp->proto_type), arp->proto_addr_len);

      printf("ARP operation: %#06x (%s)\n", ntohs(arp->operation), ntohs(arp->operation) == 1 ? "REQUEST" : "REPLY");

      if (ntohs(arp->operation) == 1) { // ARP Request
         printIP(arp->src_proto_addr);
         printf(" (");
         printMac(arp->src_hw_addr);
         printf(") asks for ");
         printIP(arp->target_proto_addr);
         printf(" (");
         printMac(arp->target_hw_addr);
         printf(")\n");
      } else { // ARP Reply
         printIP(arp->src_proto_addr);
         printf(" is at ");
         printMac(arp->src_hw_addr);
         printf(" tells -> ");
         printIP(arp->target_proto_addr);
         printf(" (");
         printMac(arp->target_hw_addr);
         printf(")\n");
      }

      // printf("\nRaw dump (%d Bytes):\n", sizeof(struct eth_hdr) + sizeof(struct arp_hdr));
		// dump(packet, sizeof(struct eth_hdr) + sizeof(struct arp_hdr));
}

void write_arp_base(u_char *packet, u_short operation) {
   struct eth_hdr *eth = (struct eth_hdr*) packet;
   struct arp_hdr *arp = (struct arp_hdr*) packet + sizeof(struct eth_hdr);

   eth->ether_type = htons(ETH_P_ARP);
   arp->hw_type = htons(1);
   arp->proto_type = htons(0x0806);
   arp->hw_addr_len = ETHER_ADDR_LEN;
   arp->proto_addr_len = 4;
   arp->operation = htons(operation);
}
