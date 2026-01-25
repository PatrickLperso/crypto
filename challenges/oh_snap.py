from Crypto.Cipher import ARC4

import os
from Crypto.Util.Padding import pad, unpad
import hashlib
import json
import requests
from Crypto.Util.number import bytes_to_long, long_to_bytes
from tqdm import tqdm

FLAG = "crypto{RC4_is_NSA_sucking_your_data}"

# deja de base RC4 est juste pas un bon PRNG

def xor(a, b):
    # ok 
    return b''.join([bytes([x ^ y]) for x, y in zip(a, b)])

def send_cmd(ciphertext, nonce):
    if not ciphertext:
        return {"error": "You must specify a ciphertext"}
    if not nonce:
        return {"error": "You must specify a nonce"}

    ciphertext = bytes.fromhex(ciphertext)
    nonce = bytes.fromhex(nonce)

    cipher = ARC4.new(nonce + FLAG.encode())
    cmd = cipher.decrypt(ciphertext)
    if cmd == b"ping":
        return {"msg": "Pong!"}
    else:
        return {"error": f"Unknown command: {cmd.hex()}"}

def send_cmd_request(ciphertext, nonce):
    return requests.get(f"https://aes.cryptohack.org/oh_snap/send_cmd/{ciphertext}/{nonce}").json()


def rc4(key: bytes, message: bytes) -> bytes:
    # KSA — Key Scheduling Algorithm
    S = list(range(256))
    j = 0
    key_len = len(key)

    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA — Pseudo-Random Generation Algorithm
    i = 0
    j = 0
    
    Keystream = [""]*256
    for b in range(len(message)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        Keystream[b] = S[(S[i] + S[j]) % 256] 

    return xor(Keystream, message)

# i = 255
# S[(S[i] + S[j])] 
# S[(S[j] + S[i])] 
# S[(S[j-S[i]] + S[i])] 
# S[(S[j-S[i-1]] + S[i-1])] 

# i = 254
# i = i-1
# j = j - S[i-1]
# S[(S[i-1]+S[j-S[i-1]])] 
# S[(S[i-1-S[i-1]]+S[j-S[i-1]])] 
# S[(S[i-2-S[i-2]]+S[j-S[i-2]])] 

# on travaille sur un bloc de 256 octet pour ne pas être embete par le modulo
def reverse_rc4(Keystream):

    S = [""]*256
    for b in reversed(range(len(message))):
        
        
        for i in reversed(range(256)):
            pass

        

# def challenge(interface_send_cmd):
#     ciphertext = b"a"*256
#     nonce = b"yolo"

#     message = bytes.fromhex(interface_send_cmd(ciphertext.hex(), nonce.hex())["error"].split(": ")[1])


if __name__ == "__main__":
    interface_send_cmd = send_cmd

    key = b"taratata"
    message = b"a"*256

    cipher = ARC4.new(key)
    ciphertext_1 = cipher.encrypt(message)

    ciphertext_2 = rc4(key, message)
    assert ciphertext_1==ciphertext_2


