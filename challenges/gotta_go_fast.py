#!/usr/bin/env python3

import time
from Crypto.Util.number import long_to_bytes
import hashlib

from pwn import *
import json
from tqdm import tqdm

r = remote('socket.cryptohack.org', 13372)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG = b'crypto{????????????????????}'

def _xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def generate_key():
    # vuln here
    current_time = int(time.time())
    key = long_to_bytes(current_time)
    return hashlib.sha256(key).digest()


def encrypt(b):
    key = generate_key()
    assert len(b) <= len(key), "Data package too large to encrypt"
    ciphertext = b''
    for i in range(len(b)):
        ciphertext += bytes([b[i] ^ key[i]])
    return ciphertext.hex()


class Challenge():
    def __init__(self):
        self.before_input = "Gotta go fast!\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_flag':
            return {"encrypted_flag": encrypt(FLAG)}

        elif your_input['option'] == 'encrypt_data':
            input_data = bytes.fromhex(your_input['input_data'])
            return {"encrypted_data": encrypt(input_data)}

        else:
            return {"error": "Invalid option"}

def resolve_challenge(interface):

    t1 = int(time.time())
    enc_flag = bytes.fromhex(interface({"option":"get_flag"})["encrypted_flag"])
    t2 = int(time.time()) + 1

    for k in tqdm(range(t1,t2)):
        key = hashlib.sha256(long_to_bytes(k)).digest()
        if b'crypto' in _xor(enc_flag, key):
            flag = _xor(enc_flag, key)
            break

    return flag


if __name__ == "__main__":
    #============= Local ============
    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = resolve_challenge(interface_)
    assert flag == FLAG

    #============= Cryptohack ============

    r.readline()
    interface_ = interface
    flag = resolve_challenge(interface_)
    assert flag == b'crypto{t00_f4st_t00_furi0u5}'