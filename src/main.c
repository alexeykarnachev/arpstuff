#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

typedef struct in_addr in_addr;
typedef struct ifreq ifreq;
typedef struct ether_arp ether_arp;

ifreq get_ifr(char* if_name) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    close(sockfd);

    return ifr;
}

// void get_ip_mac(unsigned char* mac, )

void get_mac_str(char* mac_str, unsigned char* mac) {
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

// void get_ifr_hwaddr(int fd, struct ifreq *ifr) {
// }

ether_arp request_mac(ifreq* ifr, uint32_t ip_addr) {
    /* get arp socket */
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (fd == -1) {
        perror("socket");
        exit(1);
	}

    /* will be sent to everyone */
	const unsigned char ether_broadcast_addr[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (ioctl(fd, SIOCGIFINDEX, ifr) == -1) {
        perror("ioctl");
        exit(1);
	}

	/* special socket address type used for AF_PACKET */
	struct sockaddr_ll addr = {0};
	addr.sll_family   = AF_PACKET;
	addr.sll_ifindex  = ifr->ifr_ifindex;
	addr.sll_halen    = ETHER_ADDR_LEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

	/* construct the ARP request */
    struct ether_arp req;
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = ETHER_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op  = htons(ARPOP_REQUEST);

	/* zero because that's what we're asking for */
	memset(&req.arp_tha, 0, sizeof(req.arp_tha));
	memcpy(&req.arp_tpa, &ip_addr, sizeof(req.arp_tpa));

    if (ioctl(fd, SIOCGIFADDR, ifr) == -1) {
        perror("ioctl");
        exit(1);
	}

	memcpy(&req.arp_sha, (unsigned char *) ifr->ifr_hwaddr.sa_data, sizeof(req.arp_sha));
	// memcpy(&req.arp_spa, (unsigned char *) ifr->ifr_addr.sa_data + 2, sizeof(req.arp_spa));

	/* actually send it */
	if (sendto(fd, &req, sizeof(struct ether_arp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("sendto");
        exit(1);
	}

	while (1) {
		/* can't use recvfrom() -- no network layer */
		int len = recv(fd, &req, sizeof(struct ether_arp), 0);
		if (len == -1) {
            perror("recv");
            exit(1);
		}
		if (len == 0) {   /* no response */
			continue;
		}

		unsigned int from_addr =
			(req.arp_spa[3] << 24)
		      | (req.arp_spa[2] << 16)
		      | (req.arp_spa[1] << 8)
		      | (req.arp_spa[0] << 0);
		if (from_addr != ip_addr) {
			continue;
		}

		break;
	}

    return req;
}

int main() {
    char* if_name = "wlp1s0";
    ifreq ifr = get_ifr(if_name);

    char my_mac_str[18];
    get_mac_str(my_mac_str, ifr.ifr_hwaddr.sa_data);

    char gateway_ip_str[18];
    in_addr gateway_in_addr = get_gateway_in_addr(if_name);
    inet_ntop(AF_INET, &gateway_in_addr, gateway_ip_str, INET_ADDRSTRLEN);


    char gateway_mac_str[18];
    ether_arp arpr = request_mac(&ifr, gateway_in_addr.s_addr);
    get_mac_str(gateway_mac_str, arpr.arp_sha);

    printf("my mac: %s\n", my_mac_str);
    printf("gateway ip: %s\n", gateway_ip_str);
    printf("gateway mac: %s\n", gateway_mac_str);

    return 0;
}
