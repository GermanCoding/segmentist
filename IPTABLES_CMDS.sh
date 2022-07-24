#!/bin/bash
if [ $# -ne 3 ];
    then echo "Usage ./IPTABLES_CMDS.sh <interface name> <outgoing IP> <outgoing interface>"
fi
interface = $1
ip = $2
interface_out = $3

sudo modprobe dummy
sudo ip link add $interface type dummy
sudo ip addr add 10.11.12.13 dev $interface
sudo ip link set $interface up
sudo ip route add 10.11.12.13 via $ip advmss 1000
sudo iptables -t nat -A POSTROUTING -s 10.11.12.13 -o $interface_out -j MASQUERADE
sudo iptables -A OUTPUT -p tcp --source 10.11.12.13 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000
echo "Test interface setup: IP is 10.11.12.13"
