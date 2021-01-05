#!/bin/bash

vm=$1
spice_port=$2
if=$3

echo "Starting $vm"
sudo kvm -drive file=$vm,format=qcow2,if=virtio -m 2048 -smp 4 -vga qxl \
    -spice port=$spice_port,addr=127.0.0.1,disable-ticketing -device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=com.redhat.spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent \
    -device e1000,netdev=net0 -netdev tap,id=net0,ifname=$if,script=no,downscript=no \
    -device e1000,netdev=net1 --netdev user,id=net1

