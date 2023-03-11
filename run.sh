./reset_iptables.sh

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -A FORWARD -j ACCEPT
iptables -t nat -s 192.168.0.1/24 -A POSTROUTING -j MASQUERADE
iptables -t nat -A POSTROUTING -j MASQUERADE

./arpstuff
