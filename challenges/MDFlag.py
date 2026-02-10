from itertools import cycle
from hashlib import md5
import struct
import math

import os

from pwn import *
import json
from tqdm import tqdm

r = remote('socket.cryptohack.org', 13407)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


FLAG = b'crypto{T_is_the_flag?????????????????????????}'

def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xffffffff

# Constantes MD5
S = [
     7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
     5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
     4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
     6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
]

K = [int(abs(math.sin(i + 1)) * 2**32) & 0xffffffff for i in range(64)]

def md5_compress(state, block):
    a, b, c, d = state
    M = struct.unpack('<16I', block)

    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5*i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3*i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7*i) % 16

        tmp = (a + f + K[i] + M[g]) & 0xffffffff
        a, d, c, b = d, c, b, (b + left_rotate(tmp, S[i])) & 0xffffffff

    return (
        (state[0] + a) & 0xffffffff,
        (state[1] + b) & 0xffffffff,
        (state[2] + c) & 0xffffffff,
        (state[3] + d) & 0xffffffff,
    )

# ========================
# Padding MD5
# ========================

def md5_padding(length_bytes):
    bit_len = length_bytes * 8
    padding = b'\x80'
    # on s'arrete des qu'on a atteint 448 bit
    while (length_bytes + len(padding)) % 64 != 56:
        padding += b'\x00'

    # on encode sur 64 bit la longeur du message
    padding += struct.pack('<Q', bit_len)
    return padding

# ========================
# Length Extension
# ========================

def md5_length_extension(hash_hex, len_B1, B2):
    # Reconstituer l'état interne depuis le hash
    state = struct.unpack('<4I', bytes.fromhex(hash_hex))

    # Padding de B1 (qu'on ne connaît pas)
    pad_B1 = md5_padding(len_B1)

    # Longueur totale AVANT padding final
    total_len = len_B1 + len(pad_B1) + len(B2)

    # Traiter B2 bloc par bloc
    data = B2
    if len(data) % 64 != 0:
        data += md5_padding(total_len)

    for i in range(0, len(data), 64):
        state = md5_compress(state, data[i:i+64])

    return struct.pack('<4I', *state)

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class Challenge():
    def __init__(self):
        self.before_input = "Enter data\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "message":
            data = bytes.fromhex(msg["data"])

            if len(data) < len(FLAG):
              return {"error": "Bad input"}

            salted = bxor(data, cycle(FLAG))
            return {"hash": md5(salted).hexdigest()}

        else:
            return {"error": "Invalid option"}

def resolve_challenge(interface):
    # hash(self.key + data + padding)

    message_to_sign = os.urandom(16)

    for k in range(1, 50):
        data = bytes([0]*k).hex()
        res= interface({"option":"message", "data": data })
        if not "error" in res.keys():
            flag_length = k
            hash = bytes.fromhex(res["hash"])
            break
    
    # le nombre N=4 n'est pas choisi par hasard 
    # N * flag_length +1 = 56 mod 64
    # on le choisit de facon à minimiser le padding

    length_data = 4*flag_length-1
    padding  = md5_padding(length_data)
    assert len(padding) == 9

    mask_data = []

    k=0
    found = False
    recover = b"crypto{"
    extension = b"}" + recover

    data = bytes([0]*length_data)
    hash_not_ext= bytes.fromhex(interface({"option":"message", "data": data.hex() })["hash"])
    assert (len(data))%64 == 56-1

    # ============== Cas spécial pour découvrir les 2 premiers octets =======================

    # le problème c'est que (k+1)*flag_length-1+8 = 0 mod 64 n'est pas inversible 
    # donc on ne peut pas trouver de k tel que cette donnée en entrée en multiple de 64 octets pour que '}crypto{' prenne pile la place du padding:
    # 'crypto{??????????????????????????????????????}' +'crypto{??????????????????????????????????????}' + [...] + '}crypto{'

    # Donc pour le premier byte, on va devoir être plus coriace 

    # N * flag_length +1 -1 = 56 mod 64
    # -1 => }
    # +1 => 0x80

    # On va donc devoir découvrir les deux premiers octets

    while k<128 and not found:

        data_ext = extension + bytes([k])
        mask = bxor(data_ext, padding)
        
        assert len(mask) == 9
        assert len(data_ext) == 9
        
        mask += bytes([0])
        hash_ext= bytes.fromhex(interface({"option":"message", "data": (data+mask).hex() })["hash"])

        for i in range(128):
            length_attack = md5_length_extension(hash_not_ext.hex(), length_data, bytes([i]))
            if length_attack == hash_ext:
                found = True
                # ========== redondant mais pour la clarté ============
                extension = b"}" + recover + bytes([k])
                recover += bytes([k]) +  bytes([i])
                mask = bxor(extension, padding) + bytes([0])
                break
        k+=1

    print(recover)
    print(extension)
    print(mask)

    # ============== Cas habituel pour découvrir les octets suivants =======================
    for _ in tqdm(range(len(recover), flag_length)):
        mask += bytes([0])
        for i in range(128):
            hash_ext= bytes.fromhex(interface({"option":"message", "data": (data+mask).hex() })["hash"])

            length_attack = md5_length_extension(hash_not_ext.hex(), length_data, recover[8:]+bytes([i]))
            if length_attack == hash_ext:
                recover += bytes([i])
                print(recover)
                break
    
    return recover
    

if __name__ == "__main__":

    # =========== local ===========

    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = resolve_challenge(interface_)
    assert flag == FLAG

    r.readline()
    interface_ = interface
    flag = resolve_challenge(interface_)
    assert flag == b'crypto{i_Th1nk_mdFLAG_is_B3TTER_th4n_hmac!!!!}'


