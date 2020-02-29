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

#include "arp.h"

struct target {
   u_char mac[ETHER_ADDR_LEN];
   u_char ip[4];
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
   *len = *len + 1;
   return 1;
}

void targetGuard(struct target **targets, u_int *len, u_int *hostIp) {
	struct pcap_pkthdr header;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;

	pcap_t *pcap_handle;
	int i;

	device = pcap_lookupdev(errbuf);
	if(device == NULL)
		pcap_fatal("pcap_lookupdev", errbuf);

	printf("Sniffing on device %s\n", device);

	pcap_handle = pcap_open_live(device, 4096, 0, 100, errbuf);
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
}

int main(void) {
   u_char *dev = "wlp0s26u1u6";
   struct sockaddr addr={0};
   unsigned char *injection = malloc(42);
   struct target *targets = malloc(0);
   u_int targetsLen = 0;

   printf("Using interface %s", dev);

   u_int hostIp = getIpOfInterface(dev);
   printf("Host IP: "); printIP(&hostIp); printf("\n");
   u_char hostMac[ETHER_ADDR_LEN];
   getMacOfInterface(dev, hostMac);
   printf("Host Mac: "); printMac(hostMac); printf("\n");

   targetGuard(&targets, &targetsLen, &hostIp);


   strncpy(addr.sa_data, dev, sizeof(addr.sa_data));

   write_arp_base(injection, 2);
   
   print_arp_packet(injection);

   return 0;

   int so = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
   if (so == -1) {
      fatal("socket()");
   }

   while(1) {
      int bytes = sendto(so, injection, 42, 0, &addr, sizeof(struct sockaddr_ll));
      if (bytes == -1)
         fatal("send()");

      printf("Sent %d bytes...\n", bytes);

      usleep(10000);
   }

   return 0;

	// struct pcap_pkthdr header;
	// const unsigned char *packet;
	// char errbuf[PCAP_ERRBUF_SIZE];
	// char *device;

	// pcap_t *pcap_handle;
	// int i;

	// device = pcap_lookupdev(errbuf);
	// if(device == NULL)
	// 	pcap_fatal("pcap_lookupdev", errbuf);

	// printf("Sniffing on device %s\n", device);

	// pcap_handle = pcap_open_live(device, 4096, 0, 100, errbuf);
	// if(pcap_handle == NULL)
	// 	pcap_fatal("pcap_open_live", errbuf);
	
	// for(i=0; ; i++) {
	// 	packet = pcap_next(pcap_handle, &header);
   //    print_arp_packet(packet, &header);
	// }

	// pcap_close(pcap_handle);
}

