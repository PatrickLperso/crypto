import os, sys
import json
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

import logging
logging.basicConfig(level=logging.INFO)

r = remote('socket.cryptohack.org', 13379, level = 'debug')

from deriving_symetric_keys import decrypt_flag 

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from Polhig_Hellman_DL import polhig_hellman

def send_data(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(re.search("{.*", line.decode(), re.DOTALL)[0])

def read_data():
    line = r.readline()
    return json.loads(re.search("{.*", line.decode(), re.DOTALL)[0])

if __name__ == "__main__":
    # get alice key exchange
    alice_keys_supported = read_data()

    # le point générateur A = int(alice_data["A"],16)
    bob_response = send_data({"supported":["DH64"]} )
    
    # get alice keys
    alice_data = send_data(bob_response)
    A = int(alice_data["A"],16)
    g = int(alice_data["g"],16)
    p = int(alice_data["p"],16)

    # get bob keys
    bob_data = send_data(alice_data)
    B = int(bob_data["B"],16)

    # get iv et cipher (on ne peut pas injecter comme la dernière fois)
    iv_cipher = read_data()
    iv = iv_cipher["iv"]
    cipher = iv_cipher["encrypted_flag"]
    print(iv, cipher)

    key_alice = polhig_hellman(A, g, p)
    assert pow(g, key_alice[0], p) == A

    shared_secret = pow(B,key_alice[0],p)

    flag = decrypt_flag(shared_secret, iv, cipher)
    assert flag == 'crypto{d0wn6r4d35_4r3_d4n63r0u5}'
