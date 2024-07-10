echo "setup iptables"

iptables -F
iptables -t nat -F
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --gid-owner 23333 -j REDIRECT --to-ports 12345
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --gid-owner 23333 -j REDIRECT --to-ports 12345