import os
import tpm

nb_trials = 100

for i in range(nb_trials):
	os.system("python3 hypervisor.py -c conf_hypervisor.json")
	tpm.flush_persistent_object([], True)
