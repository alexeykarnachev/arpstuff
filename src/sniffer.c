#include "core.h"

void* start_eth_sniffer(void* eth_sniffer_args) {
    static u8 bytes_buffer[1 << 16];
    ETHSnifferArgs* args = (ETHSnifferArgs*)eth_sniffer_args;
    do {
        // Wait for an incoming packet
        int packet_size = recv(
            args->eth_sock, bytes_buffer, sizeof(bytes_buffer), 0
        );
        if (packet_size == -1) {
            perror("ERROR: start_eth_sniffer, failed to recv eth packet");
            continue;
        }

        ether_header* eth_header = (ether_header*)bytes_buffer;

        // Check if the packet is for the target machine
        if (memcmp(
                eth_header->ether_dhost,
                args->attacker_mac.bytes,
                ETHER_ADDR_LEN
            )
            != 0) {
            continue;
        }

        // Modify the packet's destination MAC address to the router's MAC
        // address
        memcpy(
            eth_header->ether_dhost,
            args->gateway_mac.bytes,
            ETHER_ADDR_LEN
        );

        // Modify the packet's source MAC address to the sniffer's MAC
        // address
        memcpy(
            eth_header->ether_shost,
            args->attacker_mac.bytes,
            ETHER_ADDR_LEN
        );

        // Send the modified packet to the router
        if (send(args->eth_sock, bytes_buffer, packet_size, 0) == -1) {
            perror("ERROR: start_eth_sniffer, failed to send a request to "
                   "the gateway");
            printf("Packet size: %d\n", packet_size);
            continue;
        }
    } while (args->is_terminated == 0);

    return NULL;
}
