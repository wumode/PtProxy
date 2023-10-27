sudo ip route add default via 198.18.0.1 dev utun table 233
sudo ip route add 198.18.0.0/16 dev utun table 233
sudo ip route add 10.10.20.0/24 dev eno1 table 233
sudo ip rule add from 10.10.20.0/24 table 233