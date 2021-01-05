#!/bin/bash

tpm=$1
vm=$2
spice_port=$3
if=$4

echo "Starting $tpm"
sudo swtpm socket --tpmstate dir=$tpm --tpm2 --ctrl type=unixio,path=/$tpm/swtpm-sock & sleep 2

echo "Starting $vm"
sudo kvm -drive file=$vm,format=qcow2,if=virtio -m 2048 -smp 4 -vga qxl \
    -chardev socket,id=chrtpm,path=/$tpm/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0 \
    -spice port=$spice_port,addr=127.0.0.1,disable-ticketing -device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=com.redhat.spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent \
    -device e1000,netdev=net0 -netdev tap,id=net0,ifname=$if,script=no,downscript=no \
    -device e1000,netdev=net1 --netdev user,id=net1 

