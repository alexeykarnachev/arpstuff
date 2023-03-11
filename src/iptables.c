#include "core.h"

void reset_iptables(void) {
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
    system("iptables -F");
    system("iptables -X");
    system("iptables -t nat -F");
    system("iptables -t nat -X");
    system("iptables -t mangle -F");
    system("iptables -t mangle -X");
    system("iptables -P INPUT ACCEPT");
    system("iptables -P OUTPUT ACCEPT");
    system("iptables -P FORWARD ACCEPT");
}

void set_iptables(void) {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE");
}
