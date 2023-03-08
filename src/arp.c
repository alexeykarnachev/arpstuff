#include "core.h"

void send_arp_request(
    int sock,
    char* if_name,
    u32 source_addr_hl,
    Mac source_mac,
    u32 target_addr_hl
) {
    // ------------------------------------------------------------------
    // Build arp request
    in_addr source_in_addr = {.s_addr = source_addr_hl};
    in_addr target_in_addr = {.s_addr = target_addr_hl};

    ether_arp req = {0};
    memcpy(req.arp_sha, source_mac.bytes, ETHER_ADDR_LEN);
    memcpy(req.arp_spa, &source_in_addr, sizeof(source_in_addr));
    memcpy(req.arp_tpa, &target_in_addr, sizeof(target_in_addr));
    req.arp_hrd = htons(ARPHRD_ETHER);
    req.arp_pro = htons(ETH_P_IP);
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons(1);

    // ------------------------------------------------------------------
    // Send arp request
    sockaddr_ll addr_ll = {0};
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_protocol = htons(ETH_P_ARP);
    addr_ll.sll_ifindex = if_nametoindex(if_name);
    addr_ll.sll_halen = ETHER_ADDR_LEN;
    memset(addr_ll.sll_addr, 0xff, ETHER_ADDR_LEN);
    sockaddr* addr = (sockaddr*)&addr_ll;

    if (sendto(sock, &req, sizeof(ether_arp), 0, addr, sizeof(addr_ll))
        == -1) {
        perror("sendto");
        close(sock);
        exit(1);
    }
}

int receive_arp_response(
    int sock, u32 target_addr_hl, ether_arp* arp_res
) {
    while (1) {
        int res = recv(sock, arp_res, sizeof(ether_arp), 0);
        if (res == -1) {
            perror("recv");
            close(sock);
            exit(1);
        } else if (res == 0) {
            continue;
        }

        u32 source_addr_hl = (arp_res->arp_spa[3] << 24)
                             | (arp_res->arp_spa[2] << 16)
                             | (arp_res->arp_spa[1] << 8)
                             | (arp_res->arp_spa[0] << 0);

        if (source_addr_hl != target_addr_hl) {
            continue;
        }

        break;
    }

    return 1;
}

void print_arp_request(ether_arp req) {
    in_addr source_in_addr;
    in_addr target_in_addr;
    char source_mac_str[18] = {0};
    char target_mac_str[18] = {0};

    memcpy(&source_in_addr, &req.arp_spa, sizeof(in_addr));
    memcpy(&target_in_addr, &req.arp_tpa, sizeof(in_addr));

    Mac source_mac = {0};
    Mac target_mac = {0};
    memcpy(&source_mac.bytes, req.arp_sha, sizeof(req.arp_sha));
    memcpy(&target_mac.bytes, req.arp_tha, sizeof(req.arp_tha));

    printf("ARP request:");
    printf("\n  MAC: ");
    print_mac(source_mac);
    printf(" -> ");
    print_mac(target_mac);
    printf("\n  IP:  ");
    printf("%s -> ", inet_ntoa(source_in_addr));
    printf("%s\n", inet_ntoa(target_in_addr));
}
