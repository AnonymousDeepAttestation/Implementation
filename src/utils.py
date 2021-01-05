"""
This module contains utility functions for attestation.
"""

import json
import enum
import base64
import binascii

class Filename(enum.Enum):
    """
    Enumeration of the different filename used by the TPM. 
    """
    EK_CERTIFICATE = "ek.crt"
    EK_PUBLIC = "ek.pub"
    EK_HANDLE = "ek.handle"
    AIK_PUB_PEM = "aik_pub.pem"
    AIK_HANDLE = "aik.handle"
    AIK_NAME = "aik.name"
    CREDENTIAL = "credential.bin"
    ENCRYPTED_CREDENTIAL = "credential.encrypted"
    QUOTE = "quote.bin"
    SIGNATURE = "signature.bin"
    PCR = "pcr.bin"

def read_file(filename):
    """
    Read a file and return its binary content. \n
    @param filename : filename as string. \n
    @return data as bytes
    """
    with open(filename, mode='rb') as file:
        file_content = file.read()
    return file_content

def write_file(filename, data):
    """
    Write a file with binary data. \n
    @param filename : filename to read. \n
    @param data : data to write as bytes
    """
    with open(filename, mode='wb') as file:
        file.write(data)

def dict_to_json(dico_data):
    """
    Convert a python dict to a serialized JSON object. \n
    If the dict contain binary data, those data are converted in base64. \n
    @param dico_data : python dict. \n
    @return serialized JSON object
    """
    for key, value in dico_data.items():
        if isinstance(value, bytes):
            dico_data[key] = base64.b64encode(value).decode('utf-8')
    return json.dumps(dico_data).encode('utf-8')

def json_to_dict(json_data):
    """
    Convert a serialized JSON object to python dict. \n
    If the object contain base64 data, those data are converted in binary. \n
    @param json_data : serialized JSON object. \n
    @return python dict
    """
    dico = json.loads(json_data.decode('utf-8'))
    for key, value in dico.items():
        if isinstance(value, str) and (key == 'encrypted_credential' or key == 'ek_cert' 
                                                                     or key == 'ek_pub' 
                                                                     or key == 'aik_pub_pem'
                                                                     or key == 'quote'
                                                                     or key == 'signature'
                                                                     or key == 'pcr'
                                                                     or key == 'credential'
                                                                     or key == 'quote_nonce'):
            try:
                dico[key] = base64.decodestring(value.encode('utf-8'))
            except binascii.Error:
                pass
    return dico