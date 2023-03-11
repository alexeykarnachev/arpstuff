echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -A FORWARD -j ACCEPT
iptables -t nat -s 192.168.0.1/24 -A POSTROUTING -j MASQUERADE
iptables -t nat -A POSTROUTING -j MASQUERADE

./arpstuff
