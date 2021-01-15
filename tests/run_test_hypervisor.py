import os
import tpm

os.system("python3 hypervisor.py -c conf_hypervisor.json")
tpm.flush_persistent_object([], True)