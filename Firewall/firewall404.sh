#/bin/sh


iptables -t filter -F
iptables -t nat -F
iptables -t filter -X
iptables -t nat -X


