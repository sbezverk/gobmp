#!/usr/bin/bash
sudo sysctl -w fs.inotify.max_user_instances=64000
sudo sysctl -w net.ipv4.udp_mem='1124736 10000000 67108864'
sudo sysctl -w net.core.netdev_max_backlog=300000
sudo sysctl -w net.core.optmem_max=67108864
sudo sysctl -w net.core.rmem_default=67108864
sudo sysctl -w net.core.rmem_max=67108864
sudo sysctl -w net.core.wmem_default=67108864
sudo sysctl -w net.core.wmem_max=67108864 