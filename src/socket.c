#include "core.h"

int get_socket(int domain, int type, int protocol) {
    int sock = socket(domain, type, protocol);
    if (sock < 0) {
        perror("ERROR: get_socket, failed to get socket");
        exit(1);
    }

    return sock;
}

int get_arp_socket(void) {
    return get_socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
}

int get_icmp_socket(void) {
    return get_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
}

int get_eth_socket(char* if_name) {
    int eth_sock = get_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    sockaddr_ll addr_ll = {0};
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_ifindex = if_nametoindex(if_name);
    if (bind(eth_sock, (sockaddr*)&addr_ll, sizeof(addr_ll)) == -1) {
        perror("ERROR: get_eth_socket, failed to bind raw eth socket");
        exit(1);
    }

    return eth_sock;
}
