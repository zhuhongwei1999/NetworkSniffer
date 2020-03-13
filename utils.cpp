//
// Created by zhuhongwei on 3/12/20.
//

#include <pcap.h>
#include <time.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "protocol.h"
#include "utils.h"
#define MAC_ADDR_LEN 17

// Convert mac address to string.
char *mac_to_str(const unsigned char *mac){
    char *mac_str;
    mac_str = (char *)malloc(MAC_ADDR_LEN);
    sprintf(mac_str, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

void handle_packet(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet){
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t*)packet;

    // Handle ARP packet
    if(ntohs(eth_hdr->ether_type) == ethertype_arp){
        printf("Time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
        printf("ARP packet ");
        arp_hdr_t *arp_hdr = (arp_hdr_t *) (packet + sizeof(ethernet_hdr_t));
        if (ntohs(arp_hdr->ar_op) == arp_op_request){
            printf("Request: %s > %s\n", inet_ntoa(arp_hdr->ar_sip), inet_ntoa(arp_hdr->ar_tip));
        }
        else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
            printf("Response: %s's MAC address: %s\n", inet_ntoa(arp_hdr->ar_sip), mac_to_str(arp_hdr->ar_sha));
        }
    }

    // Handle IP packet
    else if (ntohs(eth_hdr->ether_type) == ethertype_ip){
        printf("%s", ctime((const time_t *)&pkthdr->ts.tv_sec));
        ip_hdr_t *ip_hdr = (ip_hdr_t *)(packet + sizeof(ethernet_hdr_t));
        printf("IP packet ");

        switch (ip_hdr->ip_p){
            case IPPROTO_TCP:
                printf(" TCP ");
                break;
            case IPPROTO_UDP:
                printf(" UDP ");
                break;
            case IPPROTO_ICMP:
                printf(" ICMP ");
                return;
            case IPPROTO_IP:
                printf(" IP ");
                return;
            default:
                return;
        }

        // Handle TCP packet
        if (ip_hdr->ip_p == IPPROTO_TCP)
        {
            tcp_hdr_t *tcp_hdr = (tcp_hdr_t*)(packet + sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t));
            int size_payload, size_ip, size_tcp;

            printf("%s:%d > ", inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport));
            printf("%s:%d", inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));

            size_ip = (ip_hdr->ip_hl)*4;
            size_tcp = (((tcp_hdr)->th_offx2 & 0xf0) >> 4)*4;
            size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_tcp);

            if (size_payload > 0)
                printf(" Payload: %d bytes", size_payload);
        }

        // Handle UDP packet
        else if (ip_hdr->ip_p == IPPROTO_UDP){
            udp_hdr_t *udp_hdr = (udp_hdr_t*)(packet + sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t));
            printf("%s:%d > ", inet_ntoa(ip_hdr->ip_src), ntohs(udp_hdr->uh_sport));
            printf("%s:%d", inet_ntoa(ip_hdr->ip_dst), ntohs(udp_hdr->uh_dport));
        }

        // Print packet data
        if(arg!=NULL && strcmp((char*)arg, "-i") == 0){
            printf("\n");
            int i;
            for(i=0; i<pkthdr->len; i++){
                printf(" %02x", packet[i]);
                if((i+1)%16 == 0 ){
                    printf("\n");
                }
            }
        }

        printf("\n\n");
    }
}