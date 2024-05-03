#!/usr/bin/bash
sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=0
sudo sysctl -w fs.inotify.max_user_instances=65536
sudo sysctl -w fs.inotify.max_user_watches=65536 
sudo sysctl -w net.ipv4.udp_mem='1124736 10000000 67108864'
sudo sysctl -w net.core.netdev_max_backlog=300000
sudo sysctl -w net.core.optmem_max=67108864
sudo sysctl -w net.core.rmem_default=67108864
sudo sysctl -w net.core.rmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864
sudo sysctl -w net.core.wmem_max=67108864 