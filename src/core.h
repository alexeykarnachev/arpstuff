#pragma once
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct in_addr in_addr;
typedef struct ifreq ifreq;
typedef struct ether_arp ether_arp;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_ll sockaddr_ll;
typedef struct timeval timeval;
typedef struct ether_header ether_header;

typedef uint32_t u32;
typedef unsigned char u8;

typedef struct Mac {
    unsigned char bytes[6];
} Mac;

typedef struct ARPSpoofArgs {
    int arp_sock;
    char* if_name;
    Mac attacker_mac;
    u32 gateway_addr_hl;
    Mac victim_mac;
    u32 victim_addr_hl;
    int period_sec;
    int is_terminated;
} ARPSpoofArgs;

typedef struct ETHProxyArgs {
    int eth_sock;
    Mac victim_mac;
    Mac attacker_mac;
    Mac gateway_mac;
    int is_terminated;
} ETHProxyArgs;

extern Mac BROADCAST_MAC;

int get_socket(int domain, int type, int protocol);
int get_arp_socket(void);
int get_eth_socket(char* if_name);

u32 get_netmask_hl(char* if_name);
u32 get_net_addr_hl(char* if_name, u32 addr_hl);
u32 get_gateway_addr_hl(char* if_name);
u32 get_interface_addr_hl(char* if_name);
Mac get_interface_mac(char* if_name);
sockaddr_ll get_arp_sockaddr_ll(char* if_name, Mac mac);

ether_arp build_ether_arp(
    int op,
    Mac target_mac,
    u32 target_addr_hl,
    Mac source_mac,
    u32 source_addr_hl
);
void broadcast_arp_request(
    int arp_sock,
    char* if_name,
    u32 target_addr_hl,
    u32 source_addr_hl,
    Mac source_mac
);
int receive_arp_reply(
    int arp_sock,
    u32 target_addr_hl,
    ether_arp* rep,
    int timeout_sec,
    int n_tries
);
void send_arp_spoof(
    int arp_sock,
    char* if_name,
    Mac attacker_mac,
    u32 gateway_ip,
    Mac victim_mac,
    u32 victim_ip
);
void* start_arp_spoof(void* arp_spoof_args);
int request_target_mac(
    int arp_sock,
    char* if_name,
    Mac* target_mac,
    u32 target_addr_hl,
    int timeout_sec,
    int n_tries
);

void* start_eth_proxy(void* eth_proxy_args);

void print_addr_l(u32 addr);
void print_mac(Mac mac);
void print_ether_arp(ether_arp arp);
