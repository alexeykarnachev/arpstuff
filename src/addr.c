#include "core.h"

u32 get_netmask_hl(char* if_name) {
    ifreq ifr = {0};
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    int sock = get_socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl(sock, SIOCGIFNETMASK, &ifr)");
        close(sock);
        exit(1);
    }
    sockaddr_in* addr = (sockaddr_in*)&ifr.ifr_netmask;
    u32 netmask_hl = addr->sin_addr.s_addr;

    close(sock);
    return netmask_hl;
}

u32 get_net_addr_hl(char* if_name, u32 addr_hl) {
    u32 netmask_hl = get_netmask_hl(if_name);
    return addr_hl & netmask_hl;
}

u32 get_gateway_addr_hl(char* if_name) {
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

    uint32_t gateway_addr_hl = strtol(p, NULL, 16);

    fclose(f);
    return gateway_addr_hl;
}

Mac get_interface_mac(char* if_name) {
    ifreq ifr = {0};
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    int sock = get_socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(sock, SIOCGIFHWADDR, &ifr)");
        exit(1);
    }

    Mac mac = {0};
    memcpy(&mac.bytes, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    return mac;
}

u32 get_interface_addr_hl(char* if_name) {
    ifreq ifr = {0};
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    int sock = get_socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(sock, SIOCGIFADDR, &ifr)");
        exit(1);
    }

    u32 addr_hl = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    return addr_hl;
}

void print_addr_l(u32 addr) {
    in_addr inaddr = {.s_addr = addr};
    printf("%s", inet_ntoa(inaddr));
}

void print_mac(Mac mac) {
    printf(
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac.bytes[0],
        mac.bytes[1],
        mac.bytes[2],
        mac.bytes[3],
        mac.bytes[4],
        mac.bytes[5]
    );
}
