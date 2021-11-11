import re
import os

def get_EK_mod(logfilename, vTPM_folder_path):
    with open(vTPM_folder_path + logfilename, 'r') as logfile:
            for line in reversed(list(logfile)):
                ek_pub = re.search(r'--type ek --ek ([a-f0-9]+)', line)
                if ek_pub:
                    return ek_pub.group(1)


def get_vTPMs(vTPM_folder_path): 
    list_tpm_ek = []
    for logfilename in os.listdir(vTPM_folder_path):
        list_tpm_ek.append(get_EK_mod(logfilename, vTPM_folder_path))
    return list_tpm_ek    
    

vTPM_folder_path = '/home/user/Documents/VM/'
list_ek = get_vTPMs(vTPM_folder_path)
print(list_ek)
print(len(list_ek))