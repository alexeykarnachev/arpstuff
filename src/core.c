#include "core.h"

int get_socket(int domain, int type, int protocol) {
    int sock = socket(domain, type, protocol);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    return sock;
}

int get_arp_socket(void) {
    return get_socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
}
