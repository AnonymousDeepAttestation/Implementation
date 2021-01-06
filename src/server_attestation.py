"""
This module contains functions to handle Deep Attestation \n
protocol message. It also used a variable (targets) to save server state \n
It does not support restart at the moment as the variable isn't save in persistent storage \n
The set_server_attestation_param  allow to modify the default param : \n
tpm_ca --> path to file with the Root CA and Intermediate CA of the TPM constructor \n
list_pcr_hyp --> list of pcr that a hypervisor should quote \n
normal_pcr_hyp --> path to file containing normal hypervisor pcr value \n
list_pcr_vm / normal_pcr_vm --> same thing but for VM PCR value \n
working_dir --> The TPM wrapper use file to work, the working dir will be used to store all this files
"""

import os
import re
import tpm
import shutil
import hashlib
import subprocess
from utils import *

# Default configuration
tpm_ca = "TPM_CA/TPM_bundle.pem"
normal_pcr_hyp = "Normal_PCR/pcr_hyp.data"
list_pcr_hyp = [14,15,16]
normal_pcr_vm = "Normal_PCR/pcr_vm.data"
list_pcr_vm = [14,15,16]
working_dir = "Temp/"

# Contain list of known targets with some information \n
# the key is the aik_name, for each key the value is another dic with the following information \n
# is_hypervisor \n
# credential \n
# quote_nonce \n
# list_VM (should always be empty if is_hypervisor false \n
# Example \n
# {aik1: {"is_hypervisor" : False, "credential": "tressecret", "quote_nonce": "abc123", "list_VM": []}, aik2 : {...}, ...}
targets = {}

def set_server_attestation_param(new_tpm_ca, new_normal_pcr_hyp, new_list_pcr_hyp, new_normal_pcr_vm, new_list_pcr_vm, new_working_dir):
    """
    This function is a simple setter to change default configuration of the server. \n
    All the parameters correspond to a new value.
    """
    global tpm_ca
    global normal_pcr_hyp
    global list_pcr_hyp
    global normal_pcr_vm
    global list_pcr_vm
    global working_dir
    tpm_ca = new_tpm_ca
    normal_pcr_hyp = new_normal_pcr_hyp
    list_pcr_hyp = new_list_pcr_hyp
    normal_pcr_vm = new_normal_pcr_vm
    list_pcr_vm = new_list_pcr_vm
    working_dir = new_working_dir

def verify_ek_cert(ek_cert, tpm_ca, aik_name):
    """
    Verify an EK certificate. \n
    @param ek_cert : EK certificate as bytes \n
    @param tpm_ca : path to file with the Root CA and Intermediate CA of the TPM constructor \n
    @param aik_name : name of the AIK of the target \n
    @return True if the certificate is valid otherwise return False
    """
    write_file(working_dir + aik_name + "/" +  Filename.EK_CERTIFICATE.value, ek_cert)
    subprocess.run(["openssl", "x509", "-inform", "der", "-in", working_dir + aik_name + "/" + Filename.EK_CERTIFICATE.value, "-out", working_dir + aik_name + "/tpm.pem"])
    result_verify = subprocess.run(["openssl", "verify", "-CAfile", tpm_ca, working_dir + aik_name + "/tpm.pem"], stdout=subprocess.PIPE).stdout.decode('utf-8')
    if "/tpm.pem: OK" in result_verify:
        return True
    else:
        return False

def check_pcr_value(aik_name, is_hypervisor):
    """
    Check if PCR value send by the target correspond to the normal PCR \n
    @param aik_name : name of the AIK of the target \n
    @param is_hypervisor : True if checking value of an hypervisor target, False is checking VM \n
    @return True is the value are the same, false otherwise
    """
    if is_hypervisor:
        normal_pcr = normal_pcr_hyp
    else:
        normal_pcr = normal_pcr_vm
    normal_pcr = read_file(normal_pcr)
    pcr = read_file(working_dir + aik_name + "/" + Filename.PCR.value)
    return normal_pcr == pcr

def credential_response(is_hypervisor, ek_cert, ek_pub, aik_name, aik_pub_pem): 
    """
    Get credential request data and generate a credential response packet. \n
    All input comes from the credential request packet . \n
    @param is_hypervisor : True if checking value of an hypervisor target, False is checking VM . \n
    @param ek_cert : EK certificate as bytes. \n
    @param ek_pub : EK public part as bytes. \n
    @param aik_name : AIK name as hex string. \n
    @param aik_pub_pem : AIK public part as bytes encoded in pem. \n
    @return credential response packet as python dict
    """
    if not re.fullmatch(r'^[0-9a-f]*$', aik_name):
        return {
            "type_message": "Error",
            "error_message": "Invalid AIK name"
        }
    if not os.path.exists(working_dir + aik_name):
        os.makedirs(working_dir + aik_name)
    else:
        return {
            "type_message": "Error",
            "error_message": "AIK already registered"
        }
    if is_hypervisor:
        if not verify_ek_cert(ek_cert, tpm_ca, aik_name):
            shutil.rmtree(working_dir + aik_name)
            return {
                "type_message": "Error",
                "error_message": "EK certificate invalid"
            }
    else:
        modulus = (ek_pub[-256:]).hex()
        registered_vTPM = False
        for aik, param in targets.items():
            if modulus in param["list_VM"]:
                registered_vTPM = True
                break
        if not registered_vTPM:
            shutil.rmtree(working_dir + aik_name)
            return {
                "type_message": "Error",
                "error_message": "vTPM not registered"
            }
    credential_data = os.urandom(32)
    quote_nonce = os.urandom(32)
    write_file(working_dir + aik_name + "/" + Filename.EK_PUBLIC.value, ek_pub)
    write_file(working_dir + aik_name + "/" + Filename.CREDENTIAL.value, credential_data)
    write_file(working_dir + aik_name + "/" + Filename.AIK_PUB_PEM.value, aik_pub_pem)
    tpm.make_credential(working_dir + aik_name + "/" + Filename.EK_PUBLIC.value, working_dir + aik_name + "/" + Filename.CREDENTIAL.value, aik_name, working_dir + aik_name + "/" + Filename.ENCRYPTED_CREDENTIAL.value, False)
    targets[aik_name] = {}
    targets[aik_name]["is_hypervisor"] = is_hypervisor 
    targets[aik_name]["credential"] = credential_data 
    targets[aik_name]["quote_nonce"] = quote_nonce
    targets[aik_name]["list_VM"] = []
    if is_hypervisor:
        list_pcr = list_pcr_hyp
    else:
        list_pcr = list_pcr_vm
    message = {
        "type_message": "credential_response",
        "encrypted_credential": read_file(working_dir + aik_name + "/" + Filename.ENCRYPTED_CREDENTIAL.value),
        "pcr_list": list_pcr,
        "quote_nonce": quote_nonce
    }
    return message

def attestation_response(is_hypervisor, aik_name, quote, signature, pcr, credential, list_VM):
    """
    Get an attestation and verify the attestation. \n
    All parameters come from the attestation packet. \n
    @param is_hypervisor : True if checking value of an hypervisor target, False is checking VM. \n
    @param aik_name : AIK name as hex string. \n
    @param quote : Quote as bytes. \n
    @param signature : Signature as bytes. \n
    @param pcr : Quoted PCR as bytes. \n
    @param credential : Credential as bytes. \n
    @param list_VM : List of EK as bytes. \n
    @return attestation response packet as python dict
    """
    if not aik_name in targets:
        return {
            "type_message": "Error",
            "error_message": "AIK not registered"
        }
    if credential != targets[aik_name]["credential"]:
        return {
            "type_message": "Error",
            "error_message": "Wrong Credential"
        }
    if is_hypervisor:
    	nonce = targets[aik_name]["quote_nonce"].hex() + ''.join(list_VM)
    	nonce = hashlib.sha256(nonce.encode('utf-8')).hexdigest()
    else:
    	nonce = targets[aik_name]["quote_nonce"].hex()
    write_file(working_dir + aik_name + "/" + Filename.QUOTE.value, quote)
    write_file(working_dir + aik_name + "/" + Filename.SIGNATURE.value, signature)
    write_file(working_dir + aik_name + "/" + Filename.PCR.value, pcr)
    result_verif_quote = tpm.check_quote(working_dir + aik_name + "/" + Filename.AIK_PUB_PEM.value, 
        working_dir + aik_name + "/" + Filename.QUOTE.value, 
        working_dir + aik_name + "/" + Filename.SIGNATURE.value, 
        working_dir + aik_name + "/" + Filename.PCR.value, 
        nonce)
    targets[aik_name]["quote_nonce"] = b''
    if not result_verif_quote:
        return {
            "type_message": "Error",
            "error_message": "Check quote failed"
        }
    if not check_pcr_value(aik_name, targets[aik_name]["is_hypervisor"]):
        return {
            "type_message": "Error",
            "error_message": "Wrong PCR values"
        }
    if targets[aik_name]["is_hypervisor"]:
        targets[aik_name]["list_VM"] = list_VM
    return {
        "type_message": "attestation_response",
        "attestation_result": "Attestation succeeded"
    }
