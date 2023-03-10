set -e

./build.sh

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.send_redirects=1
# 
# iptables -t nat -A PREROUTING -i wlp1s0 -p tcp --dport 80 -j REDIRECT --to-port 8080
# iptables -t nat -A PREROUTING -i wlp1s0 -p tcp --dport 443 -j REDIRECT --to-port 8080
# ip6tables -t nat -A PREROUTING -i wlp1s0 -p tcp --dport 80 -j REDIRECT --to-port 8080
# ip6tables -t nat -A PREROUTING -i wlp1s0 -p tcp --dport 443 -j REDIRECT --to-port 8080
# 
# iptables -t nat -A PREROUTING -i wlp1s0 -j DNAT --to-destination 192.168.0.1
# iptables -t nat -A POSTROUTING -o wlp1s0 -j MASQUERADE

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -i wlp1s0 -j DNAT --to-destination 192.168.0.1
iptables -t nat -A POSTROUTING -o wlp1s0 -j MASQUERADE

./arpstuff
