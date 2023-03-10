# Enable IP forwarding
# echo 0 > /proc/sys/net/ipv4/ip_forward
# 
# # Set up the iptables rules
# iptables -t nat -A PREROUTING -i eth0 -j DNAT --to-destination 192.168.0.1
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

./arpstuff
