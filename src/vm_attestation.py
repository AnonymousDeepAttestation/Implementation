"""
This module contains functions to create Deep Attestation \n
protocol message for the VM.
"""

import os
import tpm
from utils import *

working_dir = ""

def set_vm_attestation_param(new_working_dir):
    """
    This function is a simple setter to change default configuration of the VM client. \n
    @param new_working_dir : New value for the working directory. 
    """
    global working_dir
    working_dir = new_working_dir
   
def credential_request(aik_password):
    """
    Generate a credential request packet. \n
    @param aik_passwd : Password for the AIK private key. \n
    @return return a credential request message as python dict.
    """
    tpm.create_ek(working_dir + Filename.EK_HANDLE.value, working_dir + Filename.EK_PUBLIC.value)
    aik_name = tpm.create_aik(working_dir + Filename.EK_HANDLE.value, aik_password, working_dir + Filename.AIK_HANDLE.value, working_dir + Filename.AIK_PUB_PEM.value).replace("\n", "")
    write_file(working_dir + Filename.AIK_NAME.value, aik_name.encode("utf-8"))
    ek_pub = read_file(working_dir + Filename.EK_PUBLIC.value)
    aik_pub_pem = read_file(working_dir + Filename.AIK_PUB_PEM.value)
    message = {
        "type_message": "credential_request",
        "is_hypervisor": False,
        "ek_cert": b'',
        "ek_pub": ek_pub,
        "aik_name": aik_name,
        "aik_pub_pem": aik_pub_pem
    }
    return message

def get_credential(encrypted_credential, aik_password):
    """
    Decrypt encreypted credential. \n
    @param encrypted_credential : The encrypted credential as bytes. \n
    @param aik_passwd : Password for the AIK private key.
    """
    write_file(working_dir + Filename.ENCRYPTED_CREDENTIAL.value, encrypted_credential)
    tpm.activate_credential(working_dir + Filename.AIK_HANDLE.value, working_dir + Filename.EK_HANDLE.value, working_dir + Filename.ENCRYPTED_CREDENTIAL.value, aik_password, working_dir + Filename.CREDENTIAL.value, working_dir)

def attestation(pcr_list, quote_nonce, aik_password):
    """
    Perform a quote and get an attestation message. \n
    @param pcr_list : list of PCR to quote. \n
    @param quote_nonce : Nonce to include in signature to detect replay. \n
    @param aik_passwd : Password for the AIK private key. \n
    @return an attestatino message. 
    """
    tpm.get_quote(working_dir + Filename.AIK_HANDLE.value, pcr_list, quote_nonce.hex(), aik_password, working_dir + Filename.QUOTE.value, working_dir + Filename.SIGNATURE.value, working_dir + Filename.PCR.value)
    message = {
        "type_message": "attestation",
        "is_hypervisor": False,
        "aik_name": read_file(working_dir + Filename.AIK_NAME.value).decode("utf-8"),
        "quote": read_file(working_dir + Filename.QUOTE.value),
        "signature": read_file(working_dir + Filename.SIGNATURE.value),
        "pcr": read_file(working_dir + Filename.PCR.value),  
        "credential": read_file(working_dir + Filename.CREDENTIAL.value),
        "vTPMs": []
    }
    return message
