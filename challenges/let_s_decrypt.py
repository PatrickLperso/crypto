#!/usr/bin/env python3

import re
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from pkcs1 import emsa_pkcs1_v15
from Crypto.Util.number import isPrime
import random as rd
from sage.all import GF, Integer
# from params import N, E, D

# ===============================================
# ==================Mes ajouts ==================
# ===============================================
from pwn import *
import json
import string

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from crypto_core.polhig_hellman_dl import polhig_hellman, order_g_f
from sage.all import Integer

r = remote('socket.cryptohack.org', 13391, level = 'info')

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

E = 65537
p = getPrime(1024)
q = getPrime(1024)
N = p*q

phi = (p - 1) * (q - 1)
D = inverse(E, phi)

# ===============================================
# ===============================================
# ===============================================

FLAG = "crypto{?????????????????????????????????}"

MSG = 'We are hyperreality and Jack and we own CryptoHack.org'

DIGEST = emsa_pkcs1_v15.encode(MSG.encode(), 256)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)


class Challenge():
    def __init__(self):
        self.before_input = "This server validates domain ownership with RSA signatures. Present your message and public key, and if the signature matches ours, you must own the domain.\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_signature':
            return {
                "N": hex(N),
                "e": hex(E),
                "signature": hex(SIGNATURE)
            }

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            n = int(your_input['N'], 16)
            e = int(your_input['e'], 16)

            digest = emsa_pkcs1_v15.encode(msg.encode(), 256)
            calculated_digest = pow(SIGNATURE, e, n)  

            if bytes_to_long(digest) == calculated_digest: 

                r = re.match(r'^I am Mallory.*own CryptoHack.org$', msg) 
                if r:
                    return {"msg": f"Congratulations, here's a secret: {FLAG}"}
                else:
                    return {"msg": f"Ownership verified."}
            else:
                return {"error": "Invalid signature"}

        else:
            return {"error": "Invalid option"}


# def reproduce_emsa_sha1(msg_string, em_len=256):
#     # Hacher le message en SHA-1
#     h = hashlib.sha1(msg_string.encode()).digest()
    
#     # Ajouter le DigestInfo SHA-1 (Préfixe ASN.1 standard)
#     sha1_prefix = bytes.fromhex("3021300906052b0e03021a05000414")
#     data_to_pad = sha1_prefix + h
    
#     # Appliquer le padding PKCS#1 v1.5
#     header = bytes([0, 1])
#     ps_len = em_len - 3 - len(data_to_pad)
#     ps = bytes([255]) * ps_len
    
#     return header + ps + bytes([0]) + data_to_pad

def recover(interface):

    res = interface({'option':'get_signature'})
    N, e, signature = int(res["N"],16), int(res["e"],16), int(res["signature"],16)


    message = 'I am Malloryown CryptoHack.org'
    h = bytes_to_long(emsa_pkcs1_v15.encode(message.encode(), 256))
    e = 1

    # h = s ^ e mod N
    # e = 1
    # h = s mod N
    # h - s = 0 mod N
    # h - s = k * N
    # 
    # si k = 1
    # N = h - s  

    # attention au bug de merde si n'est négatif
    N = abs(h - signature)

    res = interface({'option':'verify', "N":hex(N), "e":hex(e),"msg":message})["msg"].split(": ")[1]
    return res


if __name__ == "__main__":
    # ===== local =====
    challenge = Challenge()
    interface_ = challenge.challenge

    assert DIGEST == reproduce_emsa_sha1(MSG, em_len=256)

    flag = recover(interface_)
    assert flag == FLAG

    # ===== cryptohack =====
    r.readline()
    interface_ = interface

    flag = recover(interface_)
    assert flag == "crypto{dupl1c4t3_s1gn4tur3_k3y_s3l3ct10n}"