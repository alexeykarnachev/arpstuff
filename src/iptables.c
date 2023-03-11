#include "core.h"

void reset_iptables(void) {
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");

    system("iptables -t filter -F");
    system("iptables -t filter -X");
    system("iptables -t nat -F");
    system("iptables -t nat -X");
    system("iptables -t mangle -F");
    system("iptables -t mangle -X");

    system("iptables -t filter -P INPUT ACCEPT");
    system("iptables -t filter -P FORWARD ACCEPT");
    system("iptables -t filter -P OUTPUT ACCEPT");
    system("iptables -t nat -P PREROUTING ACCEPT");
    system("iptables -t nat -P POSTROUTING ACCEPT");
    system("iptables -t nat -P OUTPUT ACCEPT");
    system("iptables -t mangle -P PREROUTING ACCEPT");
    system("iptables -t mangle -P OUTPUT ACCEPT");
    system("iptables -t mangle -P POSTROUTING ACCEPT");
}

void set_iptables(void) {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE");
}
