#pragma once
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
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_ll sockaddr_ll;

typedef uint32_t u32;

typedef struct Mac {
    unsigned char bytes[6];
} Mac;

int get_socket(int domain, int type, int protocol);
int get_arp_socket(void);

u32 get_netmask_hl(char* if_name);
u32 get_net_addr_hl(char* if_name, u32 addr_hl);
u32 get_gateway_addr_hl(char* if_name);
Mac get_interface_mac(char* if_name);
u32 get_interface_addr_hl(char* if_name);

void send_arp_request(
    int sock,
    char* if_name,
    u32 source_addr_hl,
    Mac source_mac,
    u32 target_addr_hl
);
int receive_arp_response(int sock, u32 target_addr_hl, ether_arp* arp_res);

void print_addr_l(u32 addr);
void print_mac(Mac mac);
void print_arp_request(ether_arp arp_req);
