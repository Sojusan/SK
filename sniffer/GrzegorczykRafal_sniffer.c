#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

/* urzadzenie do nasluchiwania */
#define DEVICE "enp3s0"

/* maski dla DNS */
#define QR_MASK 32768
#define OPCODE_MASK 30720
#define AA_MASK 1024
#define TC_MASK 512
#define RD_MASK 256
#define RA_MASK 128
#define Z_MASK 112
#define RCODE_MASK 15

/* maski dla IPv6 */
#define IP6_VERSION_MASK 0xf0000000
#define IP6_CLASS_MASK 0x0ff00000
#define IP6_FLOWINFO_MASK 0x000fffff

/* maski dla NTP */
#define LI_MASK 192
#define VN_MASK 56
#define MODE_MASK 7

/* kolory protokolow */
#define ETHERNET_COLOUR "\x1B[38;5;220m"
#define ARP_COLOUR "\x1B[38;5;130m"
#define IP4_COLOUR "\x1B[38;5;26m"
#define TCP_COLOUR "\x1B[38;5;9m"
#define UDP_COLOUR "\x1B[38;5;10m"
#define ICMP4_COLOUR "\x1B[38;5;129m"
#define DNS_COLOUR "\x1B[38;5;205m"
#define IP6_COLOUR "\x1B[38;5;150m"
#define ICMP6_COLOUR "\x1B[38;5;132m"
#define DHCP_COLOUR "\x1B[38;5;192m"
#define PROTOCOL_COLOUR "\x1B[38;5;15m"
#define IGMPV2_COLOUR "\x1B[38;5;202m"
#define NTP_COLOUR "\x1B[38;5;239m"
#define RIPV2_COLOUR "\x1B[38;5;147m"
#define RESET "\x1B[0m"

struct dnshdr
{
  __u16 id;      /* identyfikator */
  __u16 flags;   /* flagi */
  __u16 qdcount; /* okresla liczbe wpisow w sekcji zapytania */
  __u16 ancount; /* okresla liczbe rekordow zasobow w sekcji odpowiedzi */
  __u16 nscount; /* okresla liczbe rekordow serwera w sekcji zwierzchnosci */
  __u16 arcount; /* okresla liczbe rekordow zasobow w sekcji dodatkowej */
};

struct dhcphdr
{
  __u8 op;            /* operacja */
  __u8 htype;         /* typ sprzetu */
  __u8 hlen;          /* dlugosc adresu sprzetowego */
  __u8 hops;          /* liczba skokow */
  __u32 xid;          /* identyfikator transakcji */
  __u16 secs;         /* liczba sekund */
  __u16 flags;        /* flagi */
  __u32 ciaddr;       /* adres ip klienta */
  __u32 yiaddr;       /* adres ip nasz */
  __u32 siaddr;       /* adres ip serwera */
  __u32 giaddr;       /* adres ip bramki (routera) */
  __u32 chaddr;       /* adres sprzetowy klienta */
  __u32 magic_cookie; /* plik startowy */
};

struct igmpv2hdr
{
  __u8 type;           /* typ wiadomosci */
  __u8 max_resp_time;  /* maksymalny czas dowyslania wiadomosci report */
  __u16 checksum;      /* suma kontrolna */
  __u32 group_address; /* pole adresu grupy multicastowej */
};

struct ntphdr
{
  __u8 flags;                 /* flagi na wskaznik sekund przestepnych, numer wersji, tryp pracy */
  __u8 stratum;               /* warstwa, w ktorej funkcjonuje komputer bedacy nadawca komunikatu */
  __u8 poll_interval;         /* okres pomiedzy kolejnymi aktualizacjami czasu */
  __u8 precision;             /* okreslenie dokladnoscizegara komputera wysylajacego dany komunikat */
  __u32 root_delay;           /* opoznienie pomiedzy nadawca a serwerem warstwy 1 */
  __u32 root_dispersion;      /* maksymalny blad pomiedzy zegarem lokalnym a serwera warstwy 1 */
  __u32 reference_identifier; /* identyfikator zrodla czasu, wzgledem ktorego nastepuje synchronizacja */
  __u32 reference_timestamp;  /* pole zawierajace pomocnicze informacje o czasie poprzedniej synchronizacji */
  __u32 originate_timestamp;  /* pole zawierajace czas wyslania zadania przez klienta */
  __u32 receive_timestamp;    /* czas odebrania komunikatu od klienta */
  __u32 transmit_timestamp;   /* czas wyslania odpowiedzi do klienta */
};

struct ripv2hdr
{
  __u8 order;           /* opisuje czy pakiet jest zadaniem czy odpowiedzia */
  __u8 version_number;  /* numer wersji protokolu */
  __u16 routing_domain; /* numer domeny routingu */
  __u16 afi;            /* identyfikator rodziny adresow */
  __u16 route_tag;      /* znacznik trasy */
  __u32 net_address;    /* adres IP */
  __u32 subnet_mask;    /* maska podsieci adresu IP */
  __u32 next_ip;        /* adres IP naastepnego routera posredniczacego w przekazaniu pakietow */
  __u32 metrics;        /* wartosc metryki dla danej trasy */
};

void print_Ethernet_Header(char *buffer);
void print_ARP_Header(char *buffer);
void print_IP_v4_Header(char *buffer);
void print_TCP_Header(char *buffer, int size);
void print_UDP_Header(char *buffer, int size);
void print_ICMP_v4_Header(char *buffer);
void print_DNS_Header(char *buffer, int size);
void print_IP_v6_Header(char *buffer);
void print_ICMP_v6_Header(char *buffer);
void print_DHCP_Header(char *buffer);
void print_IGMPv2_Header(char *buffer);
void print_NTP_Header(char *buffer);
void print_RIPv2_Header(char *buffer);
void print_Protocols(char *buffer, int srcPort, int destPort, int size);
void print_Text(char *buffer, int size);

int main(int argc, char **argv)
{
  int saddr_size, data_size;
  struct sockaddr saddr;
  char *buffer = (char *)malloc(65536); /* bufor dla danych */

  /* utworzenie odpowiedniego socketa */
  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_raw < 0)
  {
    perror("Socket Error");
    exit(1);
  }

  /* wywolanie ioctl - ustawienie trybu promisc na naszej karcie */
  struct ifreq ifr;
  strncpy((char *)ifr.ifr_name, DEVICE, IF_NAMESIZE);
  /* pobieram wartosci flag urzadzenia */
  if (ioctl(sock_raw, SIOCGIFFLAGS, &ifr) != 0)
  {
    perror("Error ioctl");
    close(sock_raw);
    exit(1);
  }
  /* ustawiam flage promisc */
  ifr.ifr_flags |= IFF_PROMISC;
  /* ustawiam nowe wartosci flag */
  if (ioctl(sock_raw, SIOCSIFFLAGS, &ifr) != 0)
  {
    perror("Error ioctl");
    close(sock_raw);
    exit(1);
  }

  while (1)
  {
    saddr_size = sizeof saddr;
    /* odbieramy pakiety */
    data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);
    if (data_size < 0)
    {
      perror("Recvfrom error , blad odbioru pakietow\n");
      exit(1);
    }
    print_Ethernet_Header(buffer);
  }
  free(buffer);
  close(sock_raw);
  return 0;
}

void print_Ethernet_Header(char *buffer)
{
  printf(ETHERNET_COLOUR);
  struct ethhdr *eth;
  //memcpy((char *)&eth, buffer, sizeof(struct ethhdr));
  eth = (struct ethhdr *)(buffer);
  printf("\n== ETHERNET =======================\n");
  printf("Ethernet Header\n");
  printf("   |-(MAC)Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
         eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
         eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
  printf("   |-(MAC)Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
         eth->h_source[0], eth->h_source[1], eth->h_source[2],
         eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  printf("   |-Packet type: %#.4x\n", ntohs(eth->h_proto));
  printf("###############################################\n");
  printf(RESET);
  switch (ntohs(eth->h_proto))
  {
  case ETH_P_ARP:
    print_ARP_Header(buffer + sizeof(struct ethhdr));
    break;
  case ETH_P_IP:
    print_IP_v4_Header(buffer + sizeof(struct ethhdr));
    break;
  case ETH_P_IPV6:
    print_IP_v6_Header(buffer + sizeof(struct ethhdr));
    break;
  default:
    printf("Unknown protocol");
  }
}

void print_ARP_Header(char *buffer)
{
  printf(ARP_COLOUR);
  struct ether_arp *eth_arp = (struct ether_arp *)(buffer);
  printf("-= ARP =-\n");
  printf("Format of hardware address : %d\n", ntohs(eth_arp->ea_hdr.ar_hrd));
  printf("Format of protocol address : %#.4x\n", ntohs(eth_arp->ea_hdr.ar_pro));
  printf("Length MAC                 : %d\n", eth_arp->ea_hdr.ar_hln);
  printf("Length IP                  : %d\n", eth_arp->ea_hdr.ar_pln);
  printf("ARP opcode                 : %d\n", ntohs(eth_arp->ea_hdr.ar_op));
  printf("Sender hardware address    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
         eth_arp->arp_sha[0], eth_arp->arp_sha[1], eth_arp->arp_sha[2],
         eth_arp->arp_sha[3], eth_arp->arp_sha[4], eth_arp->arp_sha[5]);
  printf("Sender IP address          : %d.%d.%d.%d\n",
         eth_arp->arp_spa[0], eth_arp->arp_spa[1],
         eth_arp->arp_spa[2], eth_arp->arp_spa[3]);
  printf("Target hardware address    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
         eth_arp->arp_tha[0], eth_arp->arp_tha[1], eth_arp->arp_tha[2],
         eth_arp->arp_tha[3], eth_arp->arp_tha[4], eth_arp->arp_tha[5]);
  printf("Target IP address          : %d.%d.%d.%d\n",
         eth_arp->arp_tpa[0], eth_arp->arp_tpa[1],
         eth_arp->arp_tpa[2], eth_arp->arp_tpa[3]);
  printf("###############################################\n");
  printf(RESET);
}

void print_IP_v4_Header(char *buffer)
{
  printf(IP4_COLOUR);
  struct iphdr *ip;
  ip = (struct iphdr *)(buffer);
  printf("-= IPv4 =-\n");
  printf("IP version          : %d\n", ip->version);
  printf("IP header length    : %d\n", ip->ihl);
  printf("Differentiated Services Code Point : %d\n", ip->tos & IPTOS_DSCP_MASK);
  printf("Explicit Congestion Notification: %d\n", ip->tos & IPTOS_ECN_MASK);
  printf("Total length        : %d\n", ntohs(ip->tot_len));
  printf("Identification      : %d\n", ntohs(ip->id));
  printf("Flags:\n");
  printf("RF: %d\n", (ntohs(ip->frag_off) & IP_RF) != 0);
  printf("DF: %d\n", (ntohs(ip->frag_off) & IP_DF) != 0);
  printf("MF: %d\n", (ntohs(ip->frag_off) & IP_MF) != 0);
  printf("Fragment offset     : %#x\n", ntohs(ip->frag_off) & IP_OFFMASK);
  printf("Time To Live        : %d\n", ip->ttl);
  printf("Protocol            : %d\n", ip->protocol);
  printf("Header Checksum     : %#.4x\n", ntohs(ip->check));
  char msg[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->saddr), msg, INET_ADDRSTRLEN);
  printf("IP source           : %s\n", msg);
  inet_ntop(AF_INET, &(ip->daddr), msg, INET_ADDRSTRLEN);
  printf("IP destination      : %s\n", msg);
  printf("###############################################\n");
  printf(RESET);

  switch (ip->protocol)
  {
  case IPPROTO_TCP:
    print_TCP_Header(buffer + (ip->ihl * 4), ntohs(ip->tot_len) - ip->ihl * 4);
    break;
  case IPPROTO_UDP:
    print_UDP_Header(buffer + (ip->ihl * 4), ntohs(ip->tot_len) - ip->ihl * 4);
    break;
  case IPPROTO_ICMP:
    print_ICMP_v4_Header(buffer + (ip->ihl * 4));
    break;
  case IPPROTO_IGMP:
    print_IGMPv2_Header(buffer + (ip->ihl * 4));
    break;
  default:
    printf("Unknown Protocol\n");
  }
  printf("\n");
}

void print_TCP_Header(char *buffer, int size)
{
  printf(TCP_COLOUR);
  struct tcphdr *tcp;
  tcp = (struct tcphdr *)(buffer);
  printf("-= TCP =-\n");
  printf("Port source         : %d\n", ntohs(tcp->source));
  printf("Port destination    : %d\n", ntohs(tcp->dest));
  printf("Sequence number     : %#x\n", ntohl(tcp->seq));
  printf("Acknowledgment number: %#x\n", ntohl(tcp->ack_seq));
  printf("Data offset         : %d\n", tcp->doff);
  printf("Flags:\n");
  printf("FIN: %d\n", tcp->fin);
  printf("SYN: %d\n", tcp->syn);
  printf("RST: %d\n", tcp->rst);
  printf("PSH: %d\n", tcp->psh);
  printf("ACK: %d\n", tcp->ack);
  printf("URG: %d\n", tcp->urg);
  printf("Window size         : %d\n", ntohs(tcp->window));
  printf("Checksum            : %#.4x\n", ntohs(tcp->check));
  printf("Urgent pointer      : %d\n", ntohs(tcp->urg_ptr));
  printf("###############################################\n");
  printf(RESET);

  print_Protocols(buffer + (tcp->doff * 4), ntohs(tcp->source), ntohs(tcp->dest), size);
}

void print_UDP_Header(char *buffer, int size)
{
  printf(UDP_COLOUR);
  struct udphdr *udp;
  udp = (struct udphdr *)(buffer);
  printf("-= UDP =-\n");
  printf("Port source         : %d\n", ntohs(udp->source));
  printf("Port destination    : %d\n", ntohs(udp->dest));
  printf("Length              : %d\n", ntohs(udp->len));
  printf("Checksum            : %#.4x\n", ntohs(udp->check));
  printf("###############################################\n");
  printf(RESET);

  print_Protocols(buffer + sizeof(struct udphdr), ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
}

void print_ICMP_v4_Header(char *buffer)
{
  printf(ICMP4_COLOUR);
  struct icmphdr *icmp;
  icmp = (struct icmphdr *)(buffer);
  printf("-= ICMP =-\n");
  printf("Type               : %d\n", icmp->type);
  printf("Code               : %d\n", icmp->code);
  printf("Checksum           : %#.4x\n", ntohs(icmp->checksum));
  printf("###############################################\n\n");
  printf(RESET);
}

struct dns_query /* struktura dla DNS */
{
  __u16 type;
  __u16 class;
};

void print_DNS_Header(char *buffer, int size)
{
  printf(DNS_COLOUR);
  int length_of_name;
  length_of_name = size - 8; /* odejmuje wielkosc UDP */
  length_of_name -= 12;      /* odejmuje wielkosc DNS bez "queriers" */
  length_of_name -= 4;       /* odejmuje wielkosc ostatnich pol na typ i klase, dzieki czemu otrzymalem dlugosc nazwy */
  struct dns_query *query;
  unsigned char *name;
  name = malloc(length_of_name);
  name = (unsigned char *)(buffer + sizeof(struct dnshdr));

  query = (struct dns_query *)(buffer + sizeof(struct dnshdr) + length_of_name);

  struct dnshdr *dns;
  dns = (struct dnshdr *)(buffer);
  printf("-= DNS =-\n");
  printf("Identificator: %d\n", ntohs(dns->id));
  printf("Flags: 0x%#x\n", ntohs(dns->flags));
  printf("Response: %d\n", (ntohs(dns->flags) & QR_MASK) ? 1 : 0);
  printf("Opcode: %d\n", ntohs(dns->flags) & OPCODE_MASK);
  printf("Authoritative Answer: %d\n", (ntohs(dns->flags) & AA_MASK) ? 1 : 0);
  printf("Truncated: %d\n", (ntohs(dns->flags) & TC_MASK) ? 1 : 0);
  printf("Recursion desired: %d\n", (ntohs(dns->flags) & RD_MASK) ? 1 : 0);
  printf("Recursion available: %d\n", (ntohs(dns->flags) & RA_MASK) ? 1 : 0);
  printf("Z: %d\n", ntohs(dns->flags) & Z_MASK);
  printf("Response CODE: %d\n", ntohs(dns->flags) & RCODE_MASK);
  printf("Questions: %d\n", ntohs(dns->qdcount));
  printf("Answer RRs: %d\n", ntohs(dns->ancount));
  printf("Authority RRs: %d\n", ntohs(dns->nscount));
  printf("Additional RRs: %d\n", ntohs(dns->arcount));

  printf("Name: %s\n", name);
  printf("Type: %d\n", ntohs(query->type));
  printf("Class: %d\n", ntohs(query->class));
  printf("###############################################\n");
  printf(RESET);
}

void print_IP_v6_Header(char *buffer)
{
  printf(IP6_COLOUR);
  struct ip6_hdr *ipv6;
  ipv6 = (struct ip6_hdr *)(buffer);
  printf("-= IPv6 =-\n");
  printf("Version: %d\n", (ntohl(ipv6->ip6_flow) & IP6_VERSION_MASK) >> 28);
  printf("Traffic Class: %d\n", (ntohl(ipv6->ip6_flow) & IP6_CLASS_MASK) >> 20);
  printf("Flow Label: %d\n", ntohl(ipv6->ip6_flow) & IP6_FLOWINFO_MASK);
  printf("Payload length: %d\n", ntohs(ipv6->ip6_plen));
  printf("Next Header: %d\n", ipv6->ip6_nxt);
  printf("Hop limit: %d\n", ipv6->ip6_hlim);
  char msg[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(ipv6->ip6_src), msg, INET6_ADDRSTRLEN);
  printf("Source Address: %s\n", msg);
  inet_ntop(AF_INET6, &(ipv6->ip6_dst), msg, INET6_ADDRSTRLEN);
  printf("Destination Address: %s\n", msg);
  printf("###############################################\n");
  printf(RESET);
  switch (ipv6->ip6_nxt)
  {
  case IPPROTO_TCP:
    print_TCP_Header(buffer + sizeof(struct ip6_hdr), ntohs(ipv6->ip6_plen));
    break;
  case IPPROTO_UDP:
    print_UDP_Header(buffer + sizeof(struct ip6_hdr), ntohs(ipv6->ip6_plen));
    break;
  case IPPROTO_ICMPV6:
    print_ICMP_v6_Header(buffer + sizeof(struct ip6_hdr));
    break;
  default:
    printf("Unknown protocol\n");
  }
}

void print_ICMP_v6_Header(char *buffer)
{
  printf(ICMP6_COLOUR);
  struct icmp6_hdr *icmp6;
  icmp6 = (struct icmp6_hdr *)(buffer);
  printf("-= ICMPv6 =-\n");
  printf("Type: %d\n", icmp6->icmp6_type);
  printf("Code: %d\n", icmp6->icmp6_code);
  printf("Checksum : %#.4x\n", ntohs(icmp6->icmp6_cksum));
  printf("###############################################\n\n");
  printf(RESET);
}

void print_DHCP_Header(char *buffer)
{
  printf(DHCP_COLOUR);
  struct dhcphdr *dhcphdr;
  dhcphdr = (struct dhcphdr *)(buffer);
  printf("-= DHCP =-\n");
  printf("Operation: %d\n", dhcphdr->op);
  printf("Device type: %d\n", dhcphdr->htype);
  printf("Length of defice address: %d\n", dhcphdr->hlen);
  printf("Hops number: %d\n", dhcphdr->hops);
  printf("Transaction identificator: %#x\n", ntohl(dhcphdr->xid));
  printf("Seconds number: %d\n", ntohs(dhcphdr->secs));
  printf("Flags: %d\n", ntohs(dhcphdr->flags));
  struct in_addr addr;
  addr.s_addr = dhcphdr->ciaddr;
  printf("Client IP address: %s\n", inet_ntoa(addr));
  addr.s_addr = dhcphdr->yiaddr;
  printf("Your IP address: %s\n", inet_ntoa(addr));
  addr.s_addr = dhcphdr->siaddr;
  printf("Server IP address: %s\n", inet_ntoa(addr));
  addr.s_addr = dhcphdr->giaddr;
  printf("Gateway IP address: %s\n", inet_ntoa(addr));
  addr.s_addr = dhcphdr->chaddr;
  printf("Client hardware address: %s\n", inet_ntoa(addr));
  printf("Magic cookie: %#x\n", ntohl(dhcphdr->magic_cookie));
  printf("###############################################\n\n");
  printf(RESET);
}

void print_IGMPv2_Header(char *buffer)
{
  printf(IGMPV2_COLOUR);
  struct igmpv2hdr *igmpv2;
  igmpv2 = (struct igmpv2hdr *)(buffer);
  printf("-= IGMPv2 =-\n");
  printf("Type: %#x\n", igmpv2->type);
  printf("Max Resp Time: %#x\n", igmpv2->max_resp_time);
  printf("Checksum: %#x\n", ntohs(igmpv2->checksum));
  struct in_addr addr;
  addr.s_addr = igmpv2->group_address;
  printf("Multicast Address: %s\n", inet_ntoa(addr));
  printf("###############################################\n\n");
  printf(RESET);
}

void print_NTP_Header(char *buffer)
{
  printf(NTP_COLOUR);
  struct ntphdr *ntp;
  ntp = (struct ntphdr *)(buffer);
  printf("-= NTP =-\n");
  printf("Flags: %#x\n", ntp->flags);
  printf("Leap Indicator: %d\n", (ntp->flags & LI_MASK) >> 6);
  printf("Version number: %d\n", (ntp->flags & VN_MASK) >> 3);
  printf("Mode: %d\n", ntp->flags & MODE_MASK);
  printf("Peer Clock Stratum: %d\n", ntp->stratum);
  printf("Peer Polling Interval: %d\n", ntp->poll_interval);
  printf("Peer Clock Precision: %d\n", ntp->precision);
  printf("Root Delay: %d\n", ntohl(ntp->root_delay));
  printf("Root Dispersion: %d\n", ntohl(ntp->root_dispersion));
  struct in_addr addr;
  addr.s_addr = ntp->reference_identifier;
  printf("Reference ID: %s\n", inet_ntoa(addr));
  printf("Reference Timestamp: %#x\n", ntohl(ntp->reference_timestamp));
  printf("Origin Timestamp: %#x\n", ntohl(ntp->originate_timestamp));
  printf("Receive Timestamp: %#x\n", ntohl(ntp->receive_timestamp));
  printf("Transmit Timestamp: %#x\n", ntohl(ntp->transmit_timestamp));
  printf("###############################################\n\n");
  printf(RESET);
}

void print_RIPv2_Header(char *buffer)
{
  printf(RIPV2_COLOUR);
  struct ripv2hdr *rip;
  rip = (struct ripv2hdr *)(buffer);
  if (rip->version_number == 1)
  {
    printf("-= RIPv1 =-\n");
    printf("Command: %d\n", rip->order);
    printf("Version: %d\n", rip->version_number);
    printf("Address Family Identifier: %d\n", ntohs(rip->afi));
    struct in_addr addr;
    addr.s_addr = rip->net_address;
    printf("Network Address: %s\n", inet_ntoa(addr));
    printf("Metric: %d\n", ntohl(rip->metrics));
    printf("###############################################\n\n");
  }
  else
  {
    printf("-= RIPv2 =-\n");
    printf("Command: %d\n", rip->order);
    printf("Version: %d\n", rip->version_number);
    printf("Routing domain number: %d\n", ntohs(rip->routing_domain));
    printf("Address Family Identifier: %d\n", ntohs(rip->afi));
    printf("Route Tag: %d\n", ntohs(rip->route_tag));
    struct in_addr addr;
    addr.s_addr = rip->net_address;
    printf("Network Address: %s\n", inet_ntoa(addr));
    addr.s_addr = rip->subnet_mask;
    printf("Subnet Mask: %s\n", inet_ntoa(addr));
    addr.s_addr = rip->next_ip;
    printf("Next Hop: %s\n", inet_ntoa(addr));
    printf("Metric: %d\n", ntohl(rip->metrics));
    printf("###############################################\n\n");
  }
  printf(RESET);
}

void print_Protocols(char *buffer, int srcPort, int destPort, int size)
{
  printf(PROTOCOL_COLOUR);
  int port = srcPort < destPort ? srcPort : destPort;
  switch (port)
  {
  case 7:
    printf("-= Echo =-\n");
    break;
  case 20:
    printf("-= FTP =- (transfer data)\n");
    break;
  case 21:
    printf("-= FTP =- (transfer request)");
    break;
  case 22:
    printf("-= SSH =-\n");
    break;
  case 23:
    printf("-= Telnet =-\n");
    print_Text(buffer, size);
    break;
  case 53:
    print_DNS_Header(buffer, size);
    break;
  case 67:
    print_DHCP_Header(buffer);
    break;
  case 68:
    print_DHCP_Header(buffer);
    break;
  case 80:
    printf("-= HTTP =-\n");
    if (srcPort == 80)
    {
      print_Text(buffer, size);
    }
    break;
  case 123:
    print_NTP_Header(buffer);
    break;
  case 443:
    printf("-= HTTPS =-\n");
    break;
  case 520:
    print_RIPv2_Header(buffer);
    break;
  default:
    printf("Unknown Protocol\n");
  }
  printf("\n");
  printf(RESET);
}

void print_Text(char *buffer, int size)
{
  for (int i = 0; i < size; i++)
  {
    printf("%c", *(buffer + i));
  }
  printf("\n\n");
}