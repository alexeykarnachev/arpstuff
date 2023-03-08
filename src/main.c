#include "core.h"

void main(void) {
    char* if_name = "wlp1s0";
    Mac interface_mac = get_interface_mac(if_name);
    printf("My mac:     ");
    print_mac(interface_mac);
    printf("\n");

    printf("My ip:      ");
    u32 interface_addr_hl = get_interface_addr_hl(if_name);
    print_addr_l(interface_addr_hl);
    printf("\n");

    printf("Gateway ip: ");
    u32 gateway_addr_hl = get_gateway_addr_hl(if_name);
    print_addr_l(gateway_addr_hl);
    printf("\n");

    int sock = get_arp_socket();
    send_arp_request(
        sock, if_name, interface_addr_hl, interface_mac, gateway_addr_hl
    );

    ether_arp arp_res = {0};
    receive_arp_response(sock, gateway_addr_hl, &arp_res);
    print_arp_request(arp_res);
    close(sock);
}
