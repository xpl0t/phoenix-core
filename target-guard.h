#pragma once
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#include "arp.h"

struct target {
   u_char mac[ETHER_ADDR_LEN];
   u_char ip[4];
};

struct target_guard_args {
   char *interface;
   struct target **targets;
   u_int *len;
   u_int *hostIp;
};

void pcap_fatal(const char *failed_in, const char *errbuf) {
   printf("Fatal Error in %s: %s\n", failed_in, errbuf);
   exit(1);
}

void printTargets(struct target *targets, u_int len) {
   int i, j;
   struct target *target = targets;
   printf("%u targets:\n", len);

   for (i = 0; i < len; i++, target++) {
      for (j = 0; j < sizeof(target->mac); j++)
         printf("%x%c", (target->mac)[j], j == sizeof(target->mac)-1 ? ' ' : ':');
      for (j = 0; j < sizeof(target->ip); j++)
         printf("%u%c", (target->ip)[j], j == sizeof(target->ip)-1 ? '\n' : '.');
   }
}

int addTarget(struct target **targets, u_int *len, u_char *newMac, u_int *newIp) {
   int i = 0;
   struct target *target = *targets;
   for (i = 0; i < *len; i++, target++) {
      if (memcmp(target->ip, newIp, 4) == 0)
         return 0;
   }
   *targets = realloc(*targets, (*len + 1) * sizeof(struct target));
   target = *targets + *len;
   memcpy(target->mac, newMac, ETHER_ADDR_LEN);
   memcpy(target->ip, newIp, 4);
   (*len)++;
   return 1;
}

void* startTargetGuard(void *args) {
   struct target_guard_args *tgArgs = (struct target_guard_args*) args;
   char *interface = tgArgs->interface;
   struct target **targets = tgArgs->targets;
   u_int *len = tgArgs->len;
   u_int *hostIp = tgArgs->hostIp;

	struct pcap_pkthdr header;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	// char *device;

	pcap_t *pcap_handle;
	int i;

	// device = pcap_lookupdev(errbuf);
	// if(device == NULL)
	// 	pcap_fatal("pcap_lookupdev", errbuf);

	// printf("Sniffing on device %s\n", device);

	pcap_handle = pcap_open_live(interface, 4096, 0, 100, errbuf);
	if(pcap_handle == NULL)
		pcap_fatal("pcap_open_live", errbuf);
	
	while (1) {
		packet = pcap_next(pcap_handle, &header);
      struct eth_hdr *eth = (struct eth_hdr*) packet;
      struct arp_hdr *arp = (struct arp_hdr*) (eth + 1);

      if (eth->ether_type != htons(ETH_P_ARP))
         continue;

      u_char *targetMac = arp->src_hw_addr;
      u_int targetIp = *((u_int *) arp->src_proto_addr);

      // printf("\nChecking ");
      // printMac(targetMac);
      // printf(" (");
      // printIP(&targetIp);
      // printf(")...\n");

      if (memcmp(&targetIp, hostIp, 3) != 0) {
         // printf("Not a valid IP from this network\n");
         continue;
      }
      if (((u_char *) &targetIp)[3] == 1 || ((u_char *) &targetIp)[3] == ((u_char *) hostIp)[3]) {
         // printf("This IP is either of the gateway or of the host itself\n");
         continue;
      }

      int targetNew = addTarget(targets, len, targetMac, &targetIp);
      if (targetNew == 1) {
         printf("\nNew target found\n");
         printTargets(*targets, *len);
      } else {
         // printf("This target is already known\n");
      }

      // print_arp_packet(packet);
	}

	pcap_close(pcap_handle);
   return NULL;
}