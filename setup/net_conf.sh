#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    exit 1
fi
nb_if=$1 

# Create bridge
sudo ip link add br0 type bridge
sudo ip addr add 192.168.100.1/24 brd 192.168.100.255 dev br0
sudo ip link set dev br0 up

# Create tap interface 
for (( i=0; i<$nb_if; i++ ))
do
	sudo ip tuntap add mode tap user $(whoami)
    sudo ip link set tap$i master br0
    sudo ip link set dev tap$i up
done

# Add a DNS server to the bridge Set ageing time to zero to allow forwarding
sudo dnsmasq --interface=br0 --bind-interfaces --dhcp-range=192.168.100.50,192.168.100.254
sudo ip link set dev br0 type bridge ageing_time 0

