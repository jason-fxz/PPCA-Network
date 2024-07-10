# Tproxy 透明代理 

创建一个 `uid=0` 且 `gid!=0` 的用户

```sh
grep -qw qaq_tproxy /etc/passwd || echo "qaq_tproxy:x:0:23333:::" >> /etc/passwd 
```

在开始操作前，记得使用 `sysctl -w net.ipv4.ip_forward=1` 打开 linux ipv4 封包转发


reset.sh


```sh
echo "reset iptables"

iptables -F
iptables -t nat -F
```

setup.sh

```sh
echo "setup iptables"

iptables -F
iptables -t nat -F
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --gid-owner 23333 -j REDIRECT --to-ports 12345
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --gid-owner 23333 -j REDIRECT --to-ports 12345
```


以 qaq_tproxy 身份运行代理服务器。

```
sudo -u qaq_tproxy ./networking

```

运行 tcp 封包转发程序

```
sudo -u qaq_tproxy ./tproxy
```

