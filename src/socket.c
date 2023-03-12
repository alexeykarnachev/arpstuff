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

int receive_socket_reply(
    int sock, u8* buffer, int buffer_size, int timeout_sec
) {
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(sock, &socks);
    timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    if (select(sock + 1, &socks, NULL, NULL, &timeout) <= 0) {
        fprintf(
            stderr,
            "WARNING: receive_sock_reply, failed to select a socket\n"
        );
        return 0;
    }

    if (recv(sock, buffer, buffer_size, 0) < 0) {
        fprintf(
            stderr,
            "WARNING: receive_sock_reply, failed to recv a reply from the "
            "icmp_sock"
        );
        return 0;
    }

    return 1;
}
