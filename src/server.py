"""
Main module for the server. \n
This module can be runned with an argument which is a configuration file. \n
Thic configuration file is a JSON file with each variable of 'Server configuration' section (host, port....) \n
This server is able to handle multiple connection, each connection is processed with the connection_thread function. \n
"""

import ssl
import json
import errno
import utils
import socket
import _thread
import argparse
import server_attestation
from socket import error as SocketError

# ----------------------------- Server configuration -----------------------------

host = '192.168.100.2'
port = 4433
server_cert = 'Server_Cert/server.crt'
server_key = 'Server_Cert/server.key'
tpm_ca = 'TPM_CA/TPM_bundle.pem'
normal_pcr_hyp = 'Normal_PCR/pcr_hyp.data'
pcr_list_hyp = [14,15,16]
normal_pcr_vm = 'Normal_PCR/pcr_vm.data'
pcr_list_vm = [14,15,16]
working_dir = "Temp/"

parser = argparse.ArgumentParser(description="Server for Deep Attestation")
parser.add_argument('-c', '--config_file', type=str, help='Configuration file')
args = parser.parse_args()

if args.config_file:
    with open(args.config_file) as config_file:
        config_data = json.load(config_file)
    (host, port, server_cert, server_key, tpm_ca, normal_pcr_hyp, pcr_list_hyp, normal_pcr_vm, pcr_list_vm, working_dir) = config_data.values()

server_attestation.set_server_attestation_param(tpm_ca, normal_pcr_hyp, pcr_list_hyp, normal_pcr_vm, pcr_list_vm, working_dir)

# --------------------------------------- SSL ---------------------------------------

def connection_thread(conn, addr):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("Connection with", addr, "closed")
                break
            data = utils.json_to_dict(data)
            if data["type_message"] == "credential_request":
                print("Credential request from", addr)
                (type_message, is_hypervisor, ek_cert, ek_pub, aik_name, aik_pub_pem) = data.values()  
                response = server_attestation.credential_response(is_hypervisor, ek_cert, ek_pub, aik_name, aik_pub_pem)
                conn.send(utils.dict_to_json(response))
                if response["type_message"] == "Error":
                    print("Error with", addr, response["error_message"])
                    break
            elif data["type_message"] == "attestation":
                (type_message, is_hypervisor, aik_name, quote, signature, pcr, credential, list_VM) = data.values()
                response = server_attestation.attestation_response(is_hypervisor, aik_name, quote, signature, pcr, credential, list_VM)
                conn.send(utils.dict_to_json(response))
                if response["type_message"] == "Error":
                    print("Error with", addr, response["error_message"])
                    break
                print(addr, "Attestation succeeded")
            else:
                print("Message not supported")
        except SocketError as e:
            if e.errno != errno.ECONNRESET:
                raise 
            print("Connection reset by", addr)
    conn.close()

context = ssl.SSLContext()
context.load_cert_chain(server_cert, server_key)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((host, port))
    sock.listen()
    print('Listen on', (host, port))
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            print('Connected to', addr)
            _thread.start_new_thread(connection_thread, (conn, addr, ))
        