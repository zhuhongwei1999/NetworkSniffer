#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "utils.h"

int main(int argc, char *argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    if(argc == 2 && strcmp(argv[1], "-i")!=0 || argc > 2){
        printf("Format error.");
        return 1;
    }
    /* get a device */
    devStr = pcap_lookupdev(errBuf);
    if(devStr){
        printf("success: device: %s\nPress Ctrl-C to stop\n", devStr);
        sleep(3);
    }
    else{
        printf("error: %sn", errBuf);
        return 1;
    }

    /* open a device, wait until a packet arrives */
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if(!device){
        printf("error: pcap_open_live(): %s\n", errBuf);
        return 1;
    }

    /* wait loop forever */
    if(argc == 1){
        pcap_loop(device, -1, handle_packet, NULL);
    }
    if(argc == 2){
        pcap_loop(device, -1, handle_packet, (u_char *) argv[1]);
    }
    pcap_close(device);
    return 0;
}