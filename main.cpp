#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAC_LEN 6
#define TCPSIZE 20
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned long ulong;
typedef unsigned int uint;
typedef struct _ethernet
 {
    unsigned char dest[MAC_LEN];
    unsigned char src[MAC_LEN];
    unsigned short type;
 }ethernet;

typedef struct _ip
{
    uchar hlen : 4;
    uchar version : 4;
    uchar service;
    ushort tlen;
    ushort id;
    ushort frag;
    uchar ttl;
    uchar protocol;
    ushort checksum;
   uint src_address;
   uint dst_address;
}iph;

typedef struct _tcp
{
    unsigned short src_port;
    unsigned short dst_port;
}TCP;


 void viewMac(unsigned char *mac);
 void viewIP(const u_char *buf);
 void viewTCP(const u_char *buf);
 void PrintData(const u_char *buf);
 unsigned short ntohs(unsigned short value);
 void viewethernet(const u_char *buf)
 {
  ethernet *ph = (ethernet *)buf;
  printf("***************Ethernet header*************** \n");
  printf("eth.dmac : ");
  viewMac(ph->dest);
  printf(" eth.smac : ");
  viewMac(ph->src);
  printf(" type : %#x", ntohs(ph->type));
  switch(ntohs(ph->type)){
    case 0x800:viewIP(buf + sizeof(ethernet)); break;
    case 0x806:printf("\nARP protocol\n\n"); break;
    default:printf("\nThis protocol is not in my pcap_test\n\n");
  }
 }

 void viewMac(unsigned char *mac)
 {
    int i;
    for(i=0;i<MAC_LEN;++i)
      {
        printf("%02x", mac[i]);
        if(i<MAC_LEN-1)
        printf(":");
      }
 }
 void viewIP(const u_char *buf)
 {
  in_addr addr;
  iph * ip = (iph *) buf;
  printf("\n****************IP header****************");
  addr.s_addr = ip->src_address;
  printf("\nip.sip:%s, ", inet_ntoa(addr));
  addr.s_addr = ip->dst_address;
  printf("ip.dip:%s\n", inet_ntoa(addr));
  switch(ip->protocol)
  {
    case 6: viewTCP(buf + ip -> hlen *4 ); break;
    default: printf("\n"); break;
  }
 }

 void viewTCP(const u_char *buf)
 {
  TCP *tp = (TCP *)buf;
  printf("****************TCP header*************** \n");
  printf("tcp.sport : %d, " , ntohs(tp->src_port));
  printf("tcp.dport : %d\n", ntohs(tp->dst_port));
  PrintData(buf + TCPSIZE);
 }

 void PrintData(const u_char *buf)
 {
  printf("Data : ");
   for(int i=0;i<7;++i)
      {
        printf("%02x ", buf[i]);
      }
      printf("\n\n");
 }

unsigned short ntohs(unsigned short value)
{
  return(value <<8) | (value >>8);
} 

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    viewethernet(packet);
  }

  pcap_close(handle);
  return 0;
}
