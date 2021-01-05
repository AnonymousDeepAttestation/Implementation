import re
import argparse
import subprocess

parser = argparse.ArgumentParser(description="Create a virtual TPM. The public EK is also write in the tpm_key file")
parser.add_argument('path', metavar='P', type=str, nargs='+', help='Path to the folder where to store vTPM files')
args = parser.parse_args()

output = subprocess.run(['sudo', 'swtpm_setup', '--tpmstate', args.path[0] ,'--create-ek-cert', '--tpm2'], stdout=subprocess.PIPE).stdout.decode('utf-8')
ek_pub = re.search(r'--ek (.*) --dir', output).group(1)
with open(args.path[0] + "/tpm_key", 'w') as file:
    file.write(ek_pub)