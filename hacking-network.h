#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* Structure for Ethernet headers */
#define ETHER_ADDR_LEN 6
#define eth_hdr_LEN 14

struct eth_hdr {
   unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
   unsigned char ether_src_addr[ETHER_ADDR_LEN];  // Source MAC address
   unsigned short ether_type; // Type of Ethernet packet
};

void printMac(unsigned char *mac) {
   int i;
   for (i = 0; i < 6; i++) {
      printf("%x%s", mac[i], i != 5 ? ":" : "");
   }
}

void printIP(unsigned char *ip) {
   int i;
   for (i = 0; i < 4; i++) {
      printf("%u%s", ip[i], i != 3 ? "." : "");
   }
}

u_int getIpOfInterface(char *interface) {
   struct ifaddrs *ifaddr, *ifa;

   if (getifaddrs(&ifaddr) == -1) 
      fatal("getifaddrs()");

   for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == NULL)
         continue;

      if((strcmp(ifa->ifa_name, interface) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
         freeifaddrs(ifaddr);
         struct sockaddr_in *addr = (struct sockaddr_in*) ifa->ifa_addr;
         return addr->sin_addr.s_addr;
      }
   }

   freeifaddrs(ifaddr);
   return 0;
}

void getMacOfInterface(char *interface, u_char *mac) {
   int s, i;
   struct ifreq ifr;
   s = socket(AF_INET, SOCK_DGRAM, 0);
   strncpy(ifr.ifr_name, interface, IF_NAMESIZE);
   ioctl(s, SIOCGIFHWADDR, &ifr);
   memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
   close(s);
}