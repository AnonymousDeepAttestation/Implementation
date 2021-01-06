"""
This module is a Python wrapper for the tpm2-tools : https://github.com/tpm2-software/tpm2-tools. \n
It requires the tpm-tss (https://github.com/tpm2-software/tpm2-tss) and the tpm2-tools to be installed. \n
The tpm2-abrmd (https://github.com/tpm2-software/tpm2-abrmd) is optional but recommended, not having \n
the access broker could cause memory problems with the TPM as well as concurrency problems  if  \n
multiples process try to access the TPM.
This wrapper can be runned on a hardware TPM or on the Microsoft Simulator after running the set_emulator function. \n
If run on  a hardware TPM, the TPM must be accessible without sudo. \n
It used RSA, RSASSA and SHA-256 for signing.
"""

import os
import re
import sys
import time
import shutil
import inspect
import subprocess

# Global variables, MS TPM simulator configuration
emulator = False
emulator_host = "localhost"
emulator_port = "2321"

def tpm_cmd(command, no_tcti=False):
    """
    Function to run TPM command. \n
    Param command as string. \n
    Return stdout as utf8 string. \n
    If command send to an emulator, add the option --tcti=mssim -T mssim:host=$host,port=$port. \n
    If no_tcti option to True the command will not use the TPM, only work for makecredential and checkquote command. \n
    @param command : TPM2 command as String. \n
    @param no_tcti : set to True if the command doesn't need a TPM to run. \n
    @return the command output as string
    """
    try:
        print(command)
        command_array = command.split()
        command_array[0] = "tpm2_" + command_array[0]
        if emulator and not no_tcti:
            command_array.append("--tcti=mssim")
            command_array.append("-T")
            command_array.append("mssim:host=" + emulator_host + ",port=" + emulator_port)
        start = time.perf_counter()
        result = subprocess.run(command_array, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)# ,env=environment)
        print("time :", time.perf_counter() - start, "s")
        result.check_returncode()
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as command_err:
        print("Error command : ", command, "\nLine : ", inspect.getframeinfo(inspect.stack()[1][0]).lineno, "\nExit code : ", command_err.returncode, "\nOutput : ", command_err.output.decode('utf-8'))
        sys.exit(1)

def set_emulator(host="localhost", port=2321):
    """
    Use this function to perform tpm command on tpm emulator. \n
    The hostname and port of the tpm emulator can be changed. \n
    @param host : hostname of the simulator. \n
    @param port : port of the emulator
    """
    global emulator
    global emulator_host
    global emulator_port
    emulator = True
    emulator_host = host
    emulator_port = str(port)
    # Init TPM emulator
    if emulator:
        tpm_cmd('startup --clear')

def flush_transient_object(list_handles, flush_all=False):
    """
    Flush transient object. \n
    @param list_handles : List of file corresponding to handles of object to flush. \n
    @param flush_all: If set to True flush all handles including sessions
    """
    if list_handles:
        for handle in list_handles:
            tpm_cmd("flushcontext {handle}".format(handle=handle))
    elif flush_all:
        tpm_cmd("flushcontext -t")
        tpm_cmd("flushcontext -l")
        tpm_cmd("flushcontext -s")

def flush_persistent_object(list_handles, flush_all=False):
    """
    Flush persistent object. \n
    @param list_handles : List of raw handles of persistent objects to flush
    """
    if list_handles:
        for handle in list_handles:
            tpm_cmd("evictcontrol -c {handle}".format(handle=handle))
    elif flush_all:
        all_handles = tpm_cmd("getcap handles-persistent").replace("- ", "").split("\n")
        for handle in all_handles:
            if handle:
                tpm_cmd("evictcontrol -c {handle}".format(handle=handle))

""" Old version TPM2 tools
def get_ek_cert(ek_cert):
    \"""
    Get the TPM EK certificate from NVRAM. \n
    @param ek_cert : path to a file to save the EK cert
    \"""
    nvlist = tpm_cmd('nvlist')
    size = re.split(r'0x[a-f0-9]{7}:', nvlist)[1].split("\n")[-3].split(' ')[-1]
    tpm_cmd("nvread -x 0x1c00002 -s {size} -o {ek_cert}"
        .format(size=size, ek_cert=ek_cert))
"""

def get_ek_cert(ek_cert):
    """
    Get the TPM EK certificate from NVRAM. \n
    @param ek_cert : path to a file to save the EK cert
    """
    size = tpm_cmd("nvreadpublic 0x1c00002").split("\n")[-3].split(" ")[-1]
    tpm_cmd("nvread 0x1c00002 -s {size} -o {ek_cert}"
        .format(size=size, ek_cert=ek_cert))

def create_ek(ek_handle, ek_pub):
    """
    Create an EK, serialize the handle and get the public part. \n
    @param ek_handle : path to a file to save the EK handle. \n
    @param ek_pub : path to a file to save the EK public part
    """
    raw_ek_handle = tpm_cmd("createek -c - -G rsa").split(" ")[-1].replace("\n", "")
    tpm_cmd("readpublic -c {raw_ek_handle} -o {ek_pub} -t {ek_handle}"
        .format(raw_ek_handle=raw_ek_handle, ek_pub=ek_pub, ek_handle=ek_handle))

def create_aik(ek_handle, aik_passwd, aik_handle, aik_pub_pem):
    """
    Create an AIK, serialize the handle and get the public part in pem format. \n
    @param ek_handle : path to an ek handle file. \n
    @param aik_passwd : password for the AIK. \n
    @param aik_handle : path to a file to save the AIK handle. \n
    @param aik_pub_pem : path to a file to save the AIK public part handle. \n
    @return : the AIK as hex string
    """
    aik_name = tpm_cmd("createak -C {ek_handle} -c {aik_handle} -G rsa -s rsassa -g sha256 -u {aik_pub_pem} -f pem"
        .format(ek_handle=ek_handle, aik_handle=aik_handle, aik_pub_pem=aik_pub_pem, aik_passwd=aik_passwd)).split(":")[-1].replace(" ", "")
    return aik_name

def make_credential(ek_pub, credential, aik_name, credential_encrypted, with_tpm=True):
    """
    Encrypt credential for the AIK with the public part key of EK. \n
    Credential is usually a certificate for the AIK when make credential is runned by a Privacy CA. \n
    The credential can be decrypted with activatecredential on the TPM which own the EK. \n
    This function do not require a tpm. If with_tpm is set to False all the computation will be performed by the TSS only. \n
    @param ek_pub : path to an ek public part file. \n
    @param credential : path to a file containing credential to encrypt. \n
    @param aik_name : AIK name as hex string. \n
    @param credential_encrypted : path to a file to save the encrypted credential. \n
    @with_tpm : if is set to False all the computation will be performed by the TSS only
    """
    if with_tpm:
        tpm_cmd("makecredential -e {ek_pub} -s {credential} -n {aik_name} -o {credential_encrypted}"
            .format(ek_pub=ek_pub, credential=credential, aik_name=aik_name, credential_encrypted=credential_encrypted))
    else:
        tpm_cmd("makecredential -e {ek_pub} -s {credential} -n {aik_name} -o {credential_encrypted} --tcti=none"
            .format(ek_pub=ek_pub, credential=credential, aik_name=aik_name, credential_encrypted=credential_encrypted), True)

def activate_credential(aik_handle, ek_handle, credential_encrypted, aik_passwd, credential, working_dir):
    """
    Decrypt credential which have been encrypted with make_credential. \n
    @param aik_handle : path to an aik handle file. \n
    @param ek_handle : path to an ek handle file. \n
    @param credential_encrypted : path to an encrypted credential file. \n
    @aik_passwd : password for the AIK. \n
    @param credential : path to a file to save the decrypted credential
    """
    tpm_cmd("startauthsession --policy-session -S {working_dir}session.ctx".format(working_dir=working_dir))
    tpm_cmd("policysecret -S {working_dir}session.ctx -c e".format(working_dir=working_dir))
    tpm_cmd("activatecredential -c {aik_handle} -C {ek_handle} -i {credential_encrypted} -o {credential} -P session:{working_dir}session.ctx"
        .format(aik_handle=aik_handle, ek_handle=ek_handle, credential_encrypted=credential_encrypted, credential=credential, aik_passwd=aik_passwd, working_dir=working_dir))
    tpm_cmd("flushcontext {working_dir}session.ctx".format(working_dir=working_dir))
    
def get_quote(aik_handle, pcr_list, nonce, aik_passwd, quote, signature, pcr):
    """
    Get quote from the TPM. \n
    @param aik_handle : path to an aik handle file. \n
    @param pcr_list : A list of pcr to quote. \n
    @param nonce : nonce to avoid replay attack. \n
    @param aik_passwd : password for the AIK. \n
    @param quote : path to a file to save the quote. \n
    @param signature : path to a file to save the signature. \n
    @param pcr : path to a file to save the pcr data
    """
    if not all(isinstance(pcr, int) for pcr in pcr_list):
        raise Exception('pcr_list must be a list of int')
    pcr_list = ','.join(str(pcr) for pcr in pcr_list)
    #if re.search(r'.(?![0-9a-f]+).', nonce):
    #    raise Exception('Command injection detected : get_quote - nonce')
    tpm_cmd("quote -c {aik_handle} -l sha256:{pcr_list} -q {nonce} -m {quote} -s {signature} -o {pcr} -g sha256"
        .format(aik_handle=aik_handle, aik_passwd=aik_passwd, pcr_list=pcr_list, nonce=nonce, quote=quote, signature=signature, pcr=pcr))

def check_quote(aik_pub_pem, quote, signature, pcr, nonce):
    """
    Check a quote. This function does not use a TPM. \n
    @param aik_pub_pem : path to an aik public part file in pem format. \n
    @param quote : path to a quote file. \n
    @param signature : path to a quote signature file. \n
    @param pcr : path to a pcr data file. \n
    @param nonce : the nonce used to compute the signature. \n
    @return : Return true is verification succeeded, false if failed
    """
    tpm_cmd("checkquote -u {aik_pub_pem} -m {quote} -s {signature} -f {pcr} -g sha256 -q {nonce}"
        .format(aik_pub_pem=aik_pub_pem, quote=quote, signature=signature, pcr=pcr, nonce=nonce), True)
    # If no exception raised then the verification succeeded
    return True

def test_tpm(emulator_port=2321):
    """ 
    Exemple d'utilisation. \n
    Ne peut être et ne doit être utilise que sur un simulateur. \n
    Il est possible qu'une erreur se produise à la commande evictcontrol -c 0x81000000 -p 0x81000000. \n
    si l'access broker (tpm2-abrmd) n'est pas installé
    """
    working_dir = os.urandom(32).hex()
    os.mkdir(working_dir)
    os.chdir(working_dir)
    set_emulator(port=emulator_port)
    aik_passwd = "test"
    quote_nonce = "abc123"   
    create_ek("ek.handle", "ek.pub")
    aik_name = create_aik("ek.handle", aik_passwd, "aik.handle", "aik_pub.pem")
    credential = os.urandom(32)
    with open("credential.bin", mode="wb") as file:
        file.write(credential)
    make_credential("ek.pub", "credential.bin", aik_name, "credential.encrypted", True)
    activate_credential("aik.handle", "ek.handle", "credential.encrypted", aik_passwd, "credential.decrypted", working_dir)
    with open("credential.decrypted", mode="rb") as file:
        credential_decrypted = file.read()
    print("Credential : ", credential_decrypted)
    get_quote("aik.handle", [1,2,3], quote_nonce, aik_passwd, "quote.bin", "sig.bin", "pcr.bin")
    result_quote = check_quote("aik_pub.pem", "quote.bin", "sig.bin", "pcr.bin", quote_nonce)
    print("Quote : ", result_quote)
    os.chdir("../")
    shutil.rmtree(working_dir)
    flush_transient_object([], flush_all=True)
    flush_persistent_object([], flush_all=True)
