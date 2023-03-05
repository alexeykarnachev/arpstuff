#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


void get_mac(unsigned char* mac, char* if_name) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    close(sockfd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_mac_str(char* mac_str, unsigned char* mac) {
    sprintf(
        mac_str,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

uint32_t get_gateway(const char *if_name)
{
	FILE *f = fopen("/proc/net/route", "r");
	char buf[1024];
	do {
        if (fgets(buf, 1024, f) == NULL) {
            fprintf(stderr, "ERROR: Can't find '%s' interface in the route file\n", if_name);
            exit(1);
        }

	} while (strncmp(if_name, buf, strlen(if_name)));

	char* seps = " \t";
	char *p = strtok(buf, seps);
	p = strtok(NULL, seps);
	p = strtok(NULL, seps);
	p[8] = '\0';

	uint32_t ip = strtol(p, NULL, 16);

	fclose(f);
	return ip;
}

uint32_t get_ipv4_str(char* ip_str, uint32_t ip) {
    sprintf(
        ip_str,
        "%d.%d.%d.%d",
        ((unsigned char*)&ip)[0],
        ((unsigned char*)&ip)[1],
        ((unsigned char*)&ip)[2],
        ((unsigned char*)&ip)[3]
    );
}

int main() {
    char* if_name = "wlp1s0";

    unsigned char mac[6];
    char mac_str[18];
    get_mac(mac, if_name);
    get_mac_str(mac_str, mac);

    char gateway_str[18];
    uint32_t gateway = get_gateway(if_name);
    get_ipv4_str(gateway_str, gateway);

    printf("mac: %s\n", mac_str);
    printf("gateway: %s\n", gateway_str);
    return 0;
}
