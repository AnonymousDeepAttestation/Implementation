---
title: Deep Attestation
---

## Introduction

This document describes how to deploy and set up an architecture to run the demonstration of our Deep Attestation protocol. It can be runned on a single device provided that it is embedded with a TPM 2.0 and has virtualization capacities. All the instructions have been tested on Ubuntu Desktop 20.04.1.

#### Architecture

The architecture we are going to describe is presented in the  picture below . The PC is used as the hypervisor using KVM and we run 2 QEMU Virtual machines over it. A third virtual machine played the role of the attestation server. The computer must be equipped with a TPM 2.0 (here an OPTIGA TPM by Infineon). To provide a TPM to the VM we are using a QEMU module by IBM. The communication with both the virtual TPM and hardware TPM is made with tools following the TCG TSS2 specifications. The attestation server also uses the tools as they provide functions to ease the attestation even if it does not have  a TPM.

![](https://i.imgur.com/DgJtCUw.png)

## Installation

#### Hypervisor

###### KVM/QEMU :

First we need to install QEMU and KVM. You can use these commands on Ubuntu :

```bash=
sudo apt install qemu-kvm virt-manager
sudo adduser `id -un` libvirt
```

To connect to the VM we use spice client but you can also use OpenSSH :

```bash=
sudo apt install spice-client-gtk
```

###### Virtual TPM

Now we can install the virtual TPM module. You will need to compile it. If you have trouble you can refer to the Github page of [libtpms](https://github.com/stefanberger/libtpms) and [swtpm](https://github.com/stefanberger/swtpm).

You will need the following dependencies :

```bash=
sudo apt install git build-essential autoconf libtool libssl-dev python3-pip pkg-config libtasn1-6-dev libgnutls28-dev expect gawk socat libseccomp-dev gnutls-bin
```

Install the emulation library :

```bash=
git clone -b stable-0.7.0 --single-branch https://github.com/stefanberger/libtpms.git
cd libtpms
./autogen.sh --with-openssl --with-tpm2
make
sudo make install
sudo ldconfig
cd ..
````

and the front end emulator :


```bash=
git clone -b stable-0.5 --single-branch https://github.com/stefanberger/swtpm.git
cd swtpm
./autogen.sh --with-openssl --with-tpm2
make
sudo make install
cd src/swtpm_setup
sudo python3 setup.py install
cd ../../samples
sudo python3 setup.py install
sudo ldconfig
```

###### TPM2-tools :

Finally, we can install the TPM communication tools. On Ubuntu there are precompiled packages so you can install these tools with the commands below. If you want more recent version or a customized installation refer to the Github page of the [project](https://github.com/tpm2-software).

```bash=
sudo apt install tpm2-abrmd tpm2-tools tpm-udev
sudo adduser `id -un` tss
sudo udevadm control --reload-rules && udevadm trigger
```

###### Deep Attestation protocol

Create a folder in your home directoy. Inside this folder create a Server_Cert and a Temp folder. Then copy the files `hypervisor.py`, `hypervisor_attestation.py`, `tpm.py`, `utils.py` from the `src` directory and the `conf_hypervisor.json` file from the `config` folder.

```
\DeepAttestation
...\Server_Cert
...\Temp
...hypervisor.py
...hypervisor_attestation.py
...tpm.py
...utils.py
...conf_hypervisor.json
```


#### Virtual Machines

###### TPM2-tools :

On virtual machines we only need the TPM2-tools, you can install them in the same way that on the hypervisor.

###### Deep Attestation protocol

Follow the same procedure as installation on hypervisor but replace hypervisor python files by vm files. Same for the configuration file.

```
\DeepAttestation
...\Server_Cert
...\Temp
...vm.py
...vm_attestation.py
...tpm.py
...utils.py
...conf_vm.json
```

#### Attestation server

###### TPM2-tools :

We also need the TPM2-tools but without the access broker and resource Manager as there is no TPM.

```bash=
sudo apt install tpm2-tools
```

###### Deep Attestation protocol

Same procedure as before but create two more folders : `Ref_PCR` and `TPM_Cert`.

```
\DeepAttestation
...\Server_Cert
...\Temp
...\Ref_PCR
...\TPM_Cert
...server.py
...server_attestation.py
...tpm.py
...utils.py
...conf_server.json
```

## Set Up

In this section we describe how to launch the demonstration infrastructure as described in the diagram above. We provide scripts that you can also find in the setup folder on the GitHub repository.

#### Create vTPM

The `create_tpm.py` script creates a vTPM at the given location (folder). Use this script to create 2 vTPM each of them in a specific folder regroup in one folder as in the example.

```
\vTPM
...\tpm1
...\tpm2
```

Usage of `create_tpm.py` :

```bash=
python3 create_tpm.py ~/Documents/vTPM/tpm1/
```

#### Launch attestation server and VM with virtual TPM module

First use `net_conf.sh` to create a virtual network connecting the VMs, the attestation server and the hypervisor together through a virtual bridge :

```bash=
bash ./net_conf 3 
```

The bridge provides a DHCP server but you can manually set the addresses of the VM and server in the range `192.168.100.50/192.168.100.254`. The hypervisor is always at address `192.168.100.1`.

Then you can boot the VM with `swtpm_runvm.sh`.

```bash=
./swtpm_runvm.sh ~/Documents/vTPM/tpm0/ ~/Documents/VM/VM1.qcow2 5001 tap1
```

The first parameter is the location of the folder containing a vTPM created with `create_tpm.py`, the second the VM file, the third a port for a spice server in the VM and the last a virtual interface.

To boot the server use the `run_server.sh` which works the same but don't need a vTPM.

```bash=
./run_server.sh ~/Documents/VM/Server.qcow2 5000 tap0 
```

We can use spice client to connect to the machine with a graphical interface :

```bash=
spicy -h 127.0.0.1 -p 5000
```

#### Generate a TLS certificat for the attestation server

To establish a TLS connection with the client we need a certificate. The commands below create a private RSA key and a self signed certificate. When running `openssl req` you will be prompted about information about the server. Only the Common Name field is important. You must enter the hostname of the attestation server (run `hostname` command on the attestation server to get the hostname) as the TLS implementation of python 3.8 and upper will reject certificate without a matching host (you also need to specify in the /etc/hosts file of the VMs and hypervisor the address and hostname of the attestation server unless you install a DNS server). Run the following commands inside the Server_Cert folder on the attestation server.

```bash=
openssl genrsa -out server.orig.key 2048
openssl rsa -in server.orig.key -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```

Copy the `server.crt` file in the `Server_Cert` folder created during the installation on the hypervisor and VM (you can use scp to copy files on other machine). 

#### Generates reference values of PCR

The attestation server needs to know the reference state of PCRs to verify that the current state of a VM or hypervisor PCRs and the reference PCRs match. To get those reference values you have to run the following commands.

```bash=
tpm2_createek -c ek.handle
tpm2_createak -C ek.handle -c ak.handle
# Replace 1,2,3 with PCRs you want to quote
tpm2_quote -c ak.handle -l sha256:1,2,3 -o pcr.data
tpm2_flushcontext --transient-object
rm ek.handke ak.handle
```

The reference values are in the `pcr.data` file. Copy the pcr data files into the `Ref_PCR` folder of the attestation server.

#### Get root EK certificate of the hardware TPM

To verify that attestation keys are associated with a real TPM, the attestation server needs to get the root certificate associated with the EK certificate of the hardware TPM. Here we give an example with a Nuvoton TPM.

First get EK certificate :

```bash=
tpm2_nvread 0x1c00002 > ekcert.der
```

By reading the certificate you should find the URL address to download the root certificate :

```bash=
openssl x509 -inform der -in ekcert.der -noout -text
```

Finally we download and convert the root certificate to PEM format :

```bash=
wget https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton\ TPM\ Root\ CA\ 2111.cer -O rootCA.der
openssl x509 -inform der -in rootCA.der -out rootCA.pem
```

Copy the `rootCA.pem` file in the `TPM_Cert` folder on the attestation server.

## Configuration

In this section we describe how to use the configuration files. All the files are json files.

#### Attestation server

```json=
{
    "host" : "server",
    "port" : 4433,
    "server_cert" : "Server_Cert/server.crt",
    "server_key" : "Server_Cert/server.key",
    "tpm_ca" : "TPM_CA/rootCA.pem",
    "normal_pcr_hyp" : "Normal_PCR/pcr_hyp.data",
    "pcr_list_hyp" : [14,15,16],
    "normal_pcr_vm" : "Normal_PCR/pcr_vm.data",
    "pcr_list_vm" : [14,15,16],
    "working_dir" : "Temp/"
}
```

`host` : host name of the attestation server
`port` : port for TLS server
`server_cert` : path to attestation server TLS certificate
`server_key` : path to attestation server TLS private key
`tpm_ca` : path to hardware TPM root certificate
`normal_pcr_hyp` : path to reference PCR data for hypervisor
`pcr_list_hyp` : list of PCR to quote for hypervisor
`normal_pcr_vm` : path to reference PCR data for virtual machine
`pcr_list_vm` : list of PCR to quote for virtual machine
`working_dir` : path to a folder that can be used to store temporary files (you can use the folder `Temp` created during the installation)

#### Hypervisor

```json=
{
    "host" : "server",
    "port" : 4433,
    "server_ca" : "Server_Cert/server.crt",
    "vTPM_folder_path" : "vTPM/",
    "aik_password" : "",
    "working_dir" : "Temp/"
}
```

`host`, `port` and `working_dir` are the same as attestation server.

`server_ca` : path to attestation server TLS certificate
`vTPM_folder_path` : path to the folder containing the vTPM subfolders
`aik_password` : not used you can leave empty

#### Virtual Machines

```json=
{
    "host" : "server",
    "port" : 4433,
    "server_ca" : "Server_Cert/server.crt",
    "aik_password" : "",
    "working_dir" : "Temp/"
}
```

Same as hypervisor but without vTPM field.

## Run Protocol

First run the attestation server :

```bash=
python3 server.py -c conf_server.json
```

then you can attest the hypervisor :

```bash=
python3 hypervisor.py -c conf_hypervisor.json
```

and finally attest the virtual machines by running this on each VM:

```bash=
python3 vm.py -c conf_vm.json
```