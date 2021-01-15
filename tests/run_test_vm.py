import os
import tpm

os.system("python3 vm.py -c conf_vm.json")
tpm.flush_persistent_object([], True)
