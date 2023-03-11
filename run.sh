./reset_iptables.sh

echo 1 > /proc/sys/net/ipv4/ip_forward

# I will deal with these possible settings later, when I understand the
# iptables. For now, uncommented setting work in my local network. It
# successfully proxies packets to the router and back to the client.

# iptables -A FORWARD -j ACCEPT
# iptables -t nat -s 192.168.0.1/24 -A POSTROUTING -j MASQUERADE
# iptables -t nat -A POSTROUTING -s 192.168.0.1 -j MASQUERADE
# iptables -A OUTPUT -s 192.168.0.105 -o wlp1s0 -j ACCEPT
# iptables -t nat -A POSTROUTING -j MASQUERADE

iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE

./arpstuff
