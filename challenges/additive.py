
# Ajout du répertoire eliptic curve
import os, sys
import json
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

import logging
logging.basicConfig(level=logging.INFO)

r = remote('socket.cryptohack.org', 13380, level = 'debug')

from deriving_symetric_keys import decrypt_flag 

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
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

    # get bob keys
    bob_data = read_data()

    A = int(alice_data["A"],16)
    g = int(alice_data["g"],16)
    p = int(alice_data["p"],16)

    B = int(bob_data["B"],16)

    alice_iv_cipher = read_data()
    iv_flag = alice_iv_cipher["iv"]
    cipher_flag = alice_iv_cipher["encrypted"]
    print(cipher_flag)

    # assez simple 
    # si a*g <p (a=p//2) then A = g*a mod p = g * a <=> a = A // g
    # ou sinon calculer l'inverse modualire evidemment A = a*g mod p <=> g**-1 * A = a mod p 

    possible_a = A // g
    assert (possible_a * g ) % p == A

    shared_secret = (possible_a * B ) % p
    assert "crypto{cycl1c_6r0up_und3r_4dd1710n?}" == decrypt_flag(shared_secret, iv_flag, cipher_flag)

