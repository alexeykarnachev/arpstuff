#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct in_addr in_addr;
typedef struct ifreq ifreq;
typedef struct ether_arp ether_arp;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_ll sockaddr_ll;

in_addr get_gateway_in_addr(const char* if_name) {
    FILE* f = fopen("/proc/net/route", "r");
    char buf[1024];
    do {
        if (fgets(buf, 1024, f) == NULL) {
            fprintf(
                stderr,
                "ERROR: Can't find '%s' if in the route file\n",
                if_name
            );
            exit(1);
        }

    } while (strncmp(if_name, buf, strlen(if_name)));

    char* seps = " \t";
    char* p = strtok(buf, seps);
    p = strtok(NULL, seps);
    p = strtok(NULL, seps);
    p[8] = '\0';

    uint32_t ip = strtol(p, NULL, 16);
    struct in_addr addr = {.s_addr = ip};

    fclose(f);
    return addr;
}

ether_arp build_arp_request(
    int fd, const char* if_name, in_addr target_in_addr
) {
    ifreq ifr;
    sockaddr_ll addr = {0};
    ether_arp req = {0};

    // Get interface index and MAC address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }
    memcpy(req.arp_sha, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    // Set ARP request fields
    req.arp_hrd = htons(ARPHRD_ETHER);
    req.arp_pro = htons(ETH_P_IP);
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons(1);

    // Set source and target IP addresses
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        exit(1);
    }
    in_addr source_in_addr
        = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
    memcpy(req.arp_spa, &source_in_addr, sizeof(source_in_addr));
    memcpy(req.arp_tpa, &target_in_addr, sizeof(target_in_addr));

    // Set broadcast MAC address
    memset(addr.sll_addr, 0xff, ETHER_ADDR_LEN);
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_halen = ETHER_ADDR_LEN;

    // Print ARP request information
    printf("ARP request:\n");
    printf(
        "\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        req.arp_sha[0],
        req.arp_sha[1],
        req.arp_sha[2],
        req.arp_sha[3],
        req.arp_sha[4],
        req.arp_sha[5]
    );
    printf("\tSource IP: %s\n", inet_ntoa(source_in_addr));
    printf("\tTarget IP: %s\n", inet_ntoa(target_in_addr));

    return req;
}

void main(void) {
    char* if_name = "wlp1s0";
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (fd == -1) {
        perror("socket");
        exit(1);
    }
    in_addr gateway_in_addr = get_gateway_in_addr(if_name);
    build_arp_request(fd, if_name, gateway_in_addr);
}
