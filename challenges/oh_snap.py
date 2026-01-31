from Crypto.Cipher import ARC4

import os
from Crypto.Util.Padding import pad, unpad
import hashlib
import json
import requests
from Crypto.Util.number import bytes_to_long, long_to_bytes
from tqdm import tqdm
from collections import Counter
from random import randint
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
    # allez aiohttp async qd j'aurais la foi
    return requests.get(f"https://aes.cryptohack.org/oh_snap/send_cmd/{ciphertext}/{nonce}").json()

def ksa(key, iterations=256):

    S=list(range(256))
    i = 0
    j = 0
    key_len = len(key)

    for i in range(iterations):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S, j 

def find_length_RC4_key(interface_send_cmd):
    message = b"toto".hex()

    low = 1
    high = 256
    last_ok = 0

    while low <= high:
        mid = (low + high) // 2
        iv = (b"a" * mid).hex()

        try:
            interface_send_cmd(message, iv)
            # mid fonctionne → on peut essayer plus grand
            last_ok = mid
            low = mid + 1
        except:
            # mid échoue → clé trop longue
            high = mid - 1

    # longueur de la clé secrète RC4 (hors IV)
    return 256 - last_ok

def challenge(interface_send_cmd, nb_request_max):
    

    length_RC4_key = find_length_RC4_key(interface_send_cmd)

    key_found = b''

    for A in tqdm(range(len(key_found),length_RC4_key)):

        # on a 5% de chance que l'attaque soit réalisable
        bytes_possible = []
        nb_request = 0

        while nb_request<nb_request_max:
            message = b"a"*256

            # weak_iv = (A+3, 255, V) V is random
            V = randint(0,255)
            weak_iv = bytes([A+3,255, V])
            key_rc4 = weak_iv + key_found

            # on calcule le state jusqu'à l'étape A+2 avec le nouvel key_rc4
            # ATTENTION pour ça il faut faire A+3 rounds 
            S_A_2, j_A_2 = ksa(key_rc4, iterations=A+3)

            # on fait le chec sur les IV
            if S_A_2[0]== A+3 and S_A_2[1]==0:
                nb_request+=1

                ciphertext = bytes.fromhex(interface_send_cmd(message.hex(), weak_iv.hex())["error"].split(': ')[1])
                keystream = xor(ciphertext, message)

                # on utilise la relation si S_final[A+3] == S_{A+3}[A+3] 
                # S_{A+3}[A+3] == S_{A+2}[j_{A+3}] == S_{A+2}[j_{A+2}+S_{A+2}[A+3]+Key[A+3]]
                # ainsi S_final[A+3] == S_{A+2}[j_{A+2}+S_{A+2}[A+3]+Key[A+3]]
                # Or Keytream[0] == S_{final}[A+3]
                # donc Keystream[0] = S_{A+2}[j_{A+2}+S_{A+2}[A+3]+Key[A+3]]

                # S^-1 existe car S est une permutation, cela revient à trouver l'indice 
                # et ainsi Key[A+3] = S_{A+2}^{-1}[Keystream[0]] - j_{A+2} - S_{A+2}[A+3]
                bytes_possible.append(bytes([(S_A_2.index(keystream[0]) - j_A_2 - S_A_2[A+3])%256]))
            else:
                continue
        
        # on enleve les caractères non UTF8 et on garde le caratère le plus présent
        # note : il est très probablement possible d'améliorer le truc avec de l'entropie etc.
        # afin de drastiquement réduire le nombre de requêtes
        key_found += list(filter(lambda x:x[0][0]<=127, Counter(bytes_possible).most_common()))[0][0]
        print(key_found)
    return key_found



if __name__ == "__main__":
    # Documentation
    # https://link.springer.com/content/pdf/10.1007/3-540-45537-X_1.pdf
    # https://github.com/jackieden26/FMS-Attack/blob/master/FMS%20Presentation.pdf

    # =========== RC4 FMS local attack ==============
    interface_send_cmd = send_cmd 

    flag = challenge(interface_send_cmd, 2000)
    assert flag.decode() == FLAG

    # =========== RC4 FMS cryptohack challenge ==============
    # interface_send_cmd = send_cmd_request 
    # flag = challenge(interface_send_cmd,1000)
    # assert flag == b"crypto{w1R3d_equ1v4l3nt_pr1v4cy?!}"


