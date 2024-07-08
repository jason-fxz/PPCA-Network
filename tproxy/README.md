创建一个 `uid=0` 且 `gid!=0` 的用户

```sh
grep -qw qaq_tproxy /etc/passwd || echo "qaq_tproxy:x:0:23333:::" >> /etc/passwd 
```


在开始操作前，记得使用 `sysctl -w net.ipv4.ip_forward=1` 打开 linux ipv4 封包转发


```sh
ip rule add fwmark 1 table 100
ip route add local 0.0.0.0/0 dev lo table 100

# 代理局域网设备
iptables -t mangle -N QAQ
#  "网关所在ipv4网段" 通过运行命令"ip address | grep -w inet | awk '{print $2}'"获得，一般有多个
iptables -t mangle -A QAQ -d 127.0.0.1/8 -j RETURN
iptables -t mangle -A QAQ -d 172.25.164.164/20 -j RETURN


# 组播地址/E类地址/广播地址直连
iptables -t mangle -A QAQ -d 224.0.0.0/3 -j RETURN


#如果网关作为主路由，则加上这一句，见：https://xtls.github.io/documents/level-2/transparent_proxy/transparent_proxy.md#iptables透明代理的其它注意事项
#网关LAN_IPv4地址段，运行命令"ip address | grep -w "inet" | awk '{print $2}'"获得，是其中的一个
# iptables -t mangle -A QAQ ! -s 网关LAN_IPv4地址段 -j RETURN

# 给 TCP 打标记 1，转发至 12345 端口
# mark只有设置为1，流量才能被QAQ任意门接受
iptables -t mangle -A QAQ -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1
iptables -t mangle -A QAQ -p udp -j TPROXY --on-port 12345 --tproxy-mark 1
# 应用规则
iptables -t mangle -A PREROUTING -j QAQ 

# 代理网关本机
iptables -t mangle -N QAQ_MASK
iptables -t mangle -A QAQ_MASK -m owner --gid-owner 23333 -j RETURN
iptables -t mangle -A QAQ_MASK -d 127.0.0.1/8 -j RETURN
iptables -t mangle -A QAQ_MASK -d 172.25.164.164/20 -j RETURN
iptables -t mangle -A QAQ_MASK -d 224.0.0.0/3 -j RETURN
iptables -t mangle -A QAQ_MASK -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -p tcp -j QAQ_MASK
iptables -t mangle -A OUTPUT -p udp -j QAQ_MASK
```

以 qaq_tproxy 身份运行代理服务器。

```
ulimit -SHn 1000000
sudo -u qaq_tproxy ./main&
```