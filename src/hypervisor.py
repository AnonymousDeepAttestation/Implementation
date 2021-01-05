"""
Main module for the Hypervisor client. \n
This module can be runned with an argument which is a configuration file. \n
Thic configuration file is a JSON file with each variable of 'Client configuration' section (host, port....) \n
"""

import ssl
import json
import utils
import socket
import argparse
import hypervisor_attestation

# ------------------------ Client configuration ------------------------

host = '192.168.100.2'
port = 4433
server_ca = 'Server_CA/server.crt'
vTPM_folder_path = "vTPM/"
aik_password = "test"
working_dir = "Temp/"
        
parser = argparse.ArgumentParser(description="Hypervisor client for Deep Attestation")
parser.add_argument('-c', '--config_file', type=str, help='Configuration file')
args = parser.parse_args()

if args.config_file:
    with open(args.config_file) as config_file:
        config_data = json.load(config_file)
    (host, port, server_ca, vTPM_folder_path, aik_password, working_dir) = config_data.values()

hypervisor_attestation.set_hypervisor_attestation_param(working_dir, vTPM_folder_path)

# ---------------------------------- SSL ----------------------------------

context = ssl.create_default_context()
context.load_verify_locations(cafile=server_ca)

with socket.create_connection((host, port)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        credential_request_data = utils.dict_to_json(hypervisor_attestation.credential_request(aik_password))
        ssock.send(credential_request_data)
        credential_response_data =  utils.json_to_dict(ssock.recv(4096))
        if credential_response_data["type_message"] == "Error":
            print(credential_response_data["error_message"])
            raise Exception("Credential request failed")
        hypervisor_attestation.get_credential(credential_response_data["encrypted_credential"], aik_password)
        attestation_data = utils.dict_to_json(hypervisor_attestation.attestation(credential_response_data["pcr_list"], credential_response_data["quote_nonce"], vTPM_folder_path, aik_password))
        ssock.send(attestation_data)
        attestation_response_data = utils.json_to_dict(ssock.recv(4096))
        if attestation_response_data["type_message"] == "Error":
            print(attestation_response_data["error_message"])
            raise Exception("Attestation failed")
        print(attestation_response_data)