//
// Created by zhuhongwei on 3/12/20.
//

#ifndef NETWORKSNIFFER_UTILS_H
#define NETWORKSNIFFER_UTILS_H
char *mac_to_str(const unsigned char *mac);
void handle_packet(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
#endif //NETWORKSNIFFER_UTILS_H
