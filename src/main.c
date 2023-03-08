#include <arpa/inet.h>
#include <errno.h>
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
    ifreq ifr = {0};
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        exit(1);
    }
    in_addr source_in_addr
        = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }

    ether_arp req = {0};
    memcpy(req.arp_sha, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    memcpy(req.arp_spa, &source_in_addr, sizeof(source_in_addr));
    memcpy(req.arp_tpa, &target_in_addr, sizeof(target_in_addr));
    req.arp_hrd = htons(ARPHRD_ETHER);
    req.arp_pro = htons(ETH_P_IP);
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons(1);

    return req;
}

void get_mac_str(char mac_str[18], unsigned char mac[6]) {
    sprintf(
        mac_str,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]

    );
}

void print_in_addr(in_addr addr) {
    char buffer[INET_ADDRSTRLEN];
    const char* addr_str = inet_ntop(
        AF_INET, &addr, buffer, INET_ADDRSTRLEN
    );
    if (addr_str == NULL) {
        perror("inet_ntop");
        return;
    }
    printf("%s\n", addr_str);
}

void print_arp_request(ether_arp req) {
    in_addr source_in_addr;
    in_addr target_in_addr;
    char source_mac_str[18] = {0};
    char target_mac_str[18] = {0};

    memcpy(&source_in_addr, &req.arp_spa, sizeof(in_addr));
    memcpy(&target_in_addr, &req.arp_tpa, sizeof(in_addr));

    get_mac_str(source_mac_str, req.arp_sha);
    get_mac_str(target_mac_str, req.arp_tha);

    printf("ARP request:\n");
    printf("  MAC: %s -> %s\n", source_mac_str, target_mac_str);
    printf("  IP:  ");
    printf("%s -> ", inet_ntoa(source_in_addr));
    printf("%s\n", inet_ntoa(target_in_addr));
}

void send_arp_request(int fd, char* if_name, ether_arp arp_req) {
    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = if_nametoindex(if_name);
    addr.sll_halen = ETHER_ADDR_LEN;
    memset(addr.sll_addr, 0xff, ETHER_ADDR_LEN);

    if (sendto(
            fd,
            &arp_req,
            sizeof(ether_arp),
            0,
            (struct sockaddr*)&addr,
            sizeof(addr)
        )
        == -1) {
        perror("sendto");
        exit(1);
    }
}

int receive_arp_response(int fd, ether_arp arp_req, ether_arp* arp_res) {
    in_addr target_in_addr;
    memcpy(&target_in_addr, &arp_req.arp_tpa, sizeof(in_addr));

    int n_tries = 1;
    while (1) {
        if (n_tries == 0) {
            return 0;
        }
        int len = recv(fd, arp_res, sizeof(ether_arp), 0);
        if (len == -1) {
            printf("No data received\n");
            n_tries -= 1;
            continue;
            // return 0;
            // break;
        } else if (len == 0) {
            continue;
        }

        uint32_t from_addr = (arp_res->arp_spa[3] << 24)
                             | (arp_res->arp_spa[2] << 16)
                             | (arp_res->arp_spa[1] << 8)
                             | (arp_res->arp_spa[0] << 0);
        if (from_addr != target_in_addr.s_addr) {
            continue;
        }

        break;
    }

    return 1;
}

in_addr get_netmask_in_addr(const char* if_name) {
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("SIOCGIFNETMASK");
        close(fd);
        exit(1);
    }

    sockaddr_in* addr = (sockaddr_in*)&ifr.ifr_netmask;
    in_addr mask = addr->sin_addr;

    close(fd);
    return mask;
}

in_addr get_netbase_in_addr(
    char* if_name, in_addr base_in_addr, in_addr netmask_in_addr
) {
    in_addr netbase_in_addr;
    uint32_t b = ntohl(base_in_addr.s_addr);
    uint32_t m = ntohl(netmask_in_addr.s_addr);
    netbase_in_addr.s_addr = htonl(b & m);
    return netbase_in_addr;
}

void main(void) {
    char* if_name = "wlp1s0";
    in_addr gateway_in_addr = get_gateway_in_addr(if_name);
    in_addr netmask_in_addr = get_netmask_in_addr(if_name);
    in_addr netbase_in_addr = get_netbase_in_addr(
        if_name, gateway_in_addr, netmask_in_addr
    );

    uint32_t i = 100;
    while (i <= ~ntohl(netmask_in_addr.s_addr)) {
        in_addr target_in_addr;
        target_in_addr.s_addr = htonl(ntohl(netbase_in_addr.s_addr) + i);

        int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
        if (fd == -1) {
            perror("socket");
            exit(1);
        }

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))
            == -1) {
            perror("setsockopt");
            exit(1);
        }

        ether_arp arp_req = build_arp_request(fd, if_name, target_in_addr);

        // printf("Sending arp request...\n");
        send_arp_request(fd, if_name, arp_req);

        // printf("Receiving arp response...\n");
        ether_arp arp_res;
        if (receive_arp_response(fd, arp_req, &arp_res)) {
            printf("\n---------------------------\n");
            print_arp_request(arp_req);
            print_arp_request(arp_res);
            printf("\n---------------------------\n");
        }
        i += 1;
    }
}
