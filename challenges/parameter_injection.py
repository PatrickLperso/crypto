import os, sys
import json
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

import logging
logging.basicConfig(level=logging.INFO)

r = remote('socket.cryptohack.org', 13371, level = 'debug')

from deriving_symetric_keys import decrypt_flag 

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
    alice_data = read_data()

    # le point générateur
    A = int(alice_data["A"],16)
    g = int(alice_data["g"],16)
    p = int(alice_data["p"],16)

    # send alice key to bob and get bob key
    bob_data = send_data(alice_data)

    # on crée une clé secrète bidon et on l'envoie à Alice
    secret_key=2
    our_key = {"B":hex(pow(g,secret_key, p))}

    iv_cipher = send_data(our_key)
    iv = iv_cipher["iv"]
    cipher = iv_cipher["encrypted_flag"]

    shared_secret = pow(A, secret_key, p )
    assert 'crypto{n1c3_0n3_m4ll0ry!!!!!!!!}'== decrypt_flag(shared_secret,iv, cipher)
