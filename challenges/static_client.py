
# Ajout du répertoire eliptic curve
import os, sys
import json
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

import logging
logging.basicConfig(level=logging.INFO)

r = remote('socket.cryptohack.org', 13373, level = 'debug')

from deriving_symetric_keys import decrypt_flag 

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from crypto_core.Polhig_Hellman_DL import polhig_hellman
from tqdm import tqdm
import gmpy2

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

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

    # get alice keys

    alice_data = read_data()
    bob_data = read_data()

    A = int(alice_data["A"],16)
    g = int(alice_data["g"],16)
    p = int(alice_data["p"],16)

    B = int(bob_data["B"],16)

    alice_iv_cipher = read_data()
    iv_flag = alice_iv_cipher["iv"]
    cipher_flag = alice_iv_cipher["encrypted"]

    # # on va envoyer notre propre clé 
    alice_private_key_mitm = 10
    A_mitm = pow(g,alice_private_key_mitm,p)

    # on envoie le point A à la place du générateur car il calcul sa clé publique dessus
    bob_data_mitm = send_data({"p":long_to_bytes(p).hex(), "g":long_to_bytes(A).hex(), "A":long_to_bytes(A_mitm).hex()})
    shared_secret = int(bob_data_mitm["B"],16)

    assert "crypto{n07_3ph3m3r4l_3n0u6h}" == decrypt_flag(B_mitm, iv_flag, cipher_flag)

