echo "reset iptables"

iptables -F
iptables -t nat -F