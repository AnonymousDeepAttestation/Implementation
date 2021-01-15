#!/bin/bash

nb_trials=2

for ((trial=0; trial < nb_trials; trial++))
do
    start=$(($(date +%s%N)/1000000))
    python3 hypervisor.py -c conf_hypervisor.json
    cat commands_vm | sshpass -p user ssh user@192.168.100.101
    cat commands_vm | sshpass -p user ssh user@192.168.100.102
    cat commands_vm | sshpass -p user ssh user@192.168.100.103
    cat commands_vm | sshpass -p user ssh user@192.168.100.104
    end=$(($(date +%s%N)/1000000))
    runtime=$((end-start))
    echo $runtime >> time_seq
done

