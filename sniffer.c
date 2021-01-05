//
// Created by RavidSaadia & achiyazigi on 04/01/2021.
//

# include <stdio.h>
# include <netinet/ip.h>
# include <linux/if_packet.h>
# include <net/ethernet.h>
# include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip_icmp.h>


int main() {

    char buffer[IP_MAXPACKET];
    struct sockaddr sniff_sock;
    struct packet_mreq mr;
    struct iphdr *ip; //IP-header
    struct icmphdr *icmp; // ICMP-header

    struct sockaddr_in source; //store the source ip
    struct sockaddr_in dest; //store the destination ip
    unsigned int ipproto;
    unsigned int type;
    unsigned int code;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    while(1){
        memset(buffer,0, sizeof(buffer));
        int data_size = recvfrom(sock, buffer, IP_MAXPACKET, 0, &sniff_sock, (socklen_t*) sizeof(sniff_sock));
        if(data_size){
            ip = (struct iphdr*)(buffer + sizeof(struct  ethhdr));
            ipproto = (unsigned int)(ip->protocol);
            if(ipproto == 1){ // icmp protocol is 1
                icmp = (struct icmphdr*)(buffer + sizeof(struct  ethhdr) + sizeof(struct iphdr));
                type = icmp->type;
                code = icmp->code;
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip->saddr;
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = ip->daddr;
                printf("Got icmp packet from %s ", inet_ntoa(source.sin_addr));
                printf("to %s ",inet_ntoa(dest.sin_addr));
                printf("type : %d code: %d\n",type,code );
            }
        }
        else break;
    }
    close(sock);
    return 0;
}
