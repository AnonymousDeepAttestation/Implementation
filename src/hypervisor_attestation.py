"""
This module contains functions to create Deep Attestation \n
protocol message for the hypervisor.
"""

import os
import tpm
import hashlib
from utils import *

working_dir = ""
vTPM_folder_path = ""

def set_hypervisor_attestation_param(new_working_dir, new_vTPM_folder_path):
    """
    This function is a simple setter to change default configuration of the Hypervisor client. \n
    @param new_working_dir : New value for the working directory. \n
    @param new_vTPM_folder_path : New value for the vTPM folder path 
    """
    global working_dir
    global vTPM_folder_path
    working_dir = new_working_dir
    vTPM_folder_path = new_vTPM_folder_path

def get_vTPMs(vTPM_folder_path): 
    """
    Retireve vTPM EK public part. \n
    @param vTPM_folder_path : path to the folder where the vTPM are stored. \n
    @return list of EK as bytes
    """
    list_tpm_ek = []
    for root, folder, files in os.walk(vTPM_folder_path):
        for file in files:
            if file == "tpm_key":
                list_tpm_ek.append(read_file(vTPM_folder_path + "/" + os.path.basename(root) + "/" + file).decode("utf-8"))
    return list_tpm_ek
   
def credential_request(aik_password):
    """
    Generate a credential request packet. \n
    @param aik_passwd : Password for the AIK private key. \n
    @return return a credential request message as python dict
    """
    tpm.get_ek_cert(working_dir + Filename.EK_CERTIFICATE.value)
    tpm.create_ek(working_dir + Filename.EK_HANDLE.value, working_dir + Filename.EK_PUBLIC.value)
    aik_name = tpm.create_aik(working_dir + Filename.EK_HANDLE.value, aik_password, working_dir + Filename.AIK_HANDLE.value, working_dir + Filename.AIK_PUB_PEM.value).replace("\n", "")
    write_file(working_dir + Filename.AIK_NAME.value, aik_name.encode("utf-8"))
    ek_cert = read_file(working_dir + Filename.EK_CERTIFICATE.value)
    ek_pub = read_file(working_dir + Filename.EK_PUBLIC.value)
    aik_pub_pem = read_file(working_dir + Filename.AIK_PUB_PEM.value)
    message = {
        "type_message": "credential_request",
        "is_hypervisor": True,
        "ek_cert": ek_cert,
        "ek_pub": ek_pub,
        "aik_name": aik_name,
        "aik_pub_pem": aik_pub_pem
    }
    return message

def get_credential(encrypted_credential, aik_password):
    """
    Decrypt encreypted credential. \n
    @param encrypted_credential : The encrypted credential as bytes. \n
    @param aik_passwd : Password for the AIK private key
    """
    write_file(working_dir + Filename.ENCRYPTED_CREDENTIAL.value, encrypted_credential)
    tpm.activate_credential(working_dir + Filename.AIK_HANDLE.value, working_dir + Filename.EK_HANDLE.value, working_dir + Filename.ENCRYPTED_CREDENTIAL.value, aik_password, working_dir + Filename.CREDENTIAL.value, working_dir)

def attestation(pcr_list, quote_nonce, vTPM_folder_path, aik_password):
    """
    Perform a quote and get an attestation message. \n
    @param pcr_list : list of PCR to quote. \n
    @param quote_nonce : Nonce to include in signature to detect replay. \n
    @param vTPM_folder_path : path to the folder where the vTPM are stored. \n
    @param aik_passwd : Password for the AIK private key. \n
    @return an attestatino message
    """
    vTPMs = get_vTPMs(vTPM_folder_path)
    nonce = quote_nonce.hex() + ''.join(vTPMs)
    nonce = hashlib.sha256(nonce.encode('utf-8')).hexdigest()
    tpm.get_quote(working_dir + Filename.AIK_HANDLE.value, pcr_list, nonce, aik_password, working_dir + Filename.QUOTE.value, working_dir + Filename.SIGNATURE.value, working_dir + Filename.PCR.value)
    message = {
        "type_message": "attestation",
        "is_hypervisor": True,
        "aik_name": read_file(working_dir + Filename.AIK_NAME.value).decode("utf-8"),
        "quote": read_file(working_dir + Filename.QUOTE.value),
        "signature": read_file(working_dir + Filename.SIGNATURE.value),
        "pcr": read_file(working_dir + Filename.PCR.value),  
        "credential": read_file(working_dir + Filename.CREDENTIAL.value),
        "vTPMs": vTPMs
    }
    return message
