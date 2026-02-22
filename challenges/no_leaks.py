import base64
import time
from Crypto.Util.number import long_to_bytes
import hashlib

from pwn import *
import json
from tqdm import tqdm
import numpy as np

r = remote('socket.cryptohack.org', 13370)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG= 'crypto{azertyuiop??}'

def xor_flag_with_otp():
    flag_ord = [ord(c) for c in FLAG]

    # on peut supposer que le flag fait 20 caractères
    otp = os.urandom(20)

    xored = bytearray([a ^ b for a, b in zip(flag_ord, otp)])

    # make sure our OTP doesnt leak any bytes from the flag
    for c, p in zip(xored, flag_ord):
        assert c != p

    return xored


class Challenge():
    def __init__(self):
        self.before_input = "No leaks\n"

    def challenge(self, your_input):
        if your_input == {"msg": "request"}:
            try:
                ciphertext = xor_flag_with_otp()
            except AssertionError:
                return {"error": "Leaky ciphertext"}

            ct_b64 = base64.b64encode(ciphertext)
            return {"ciphertext": ct_b64.decode()}
        else:
            self.exit = True
            return {"error": "Please request OTP"}


def resolve_challenge(interface):

    nb_samples = 1750
    otps = []
    for k in tqdm(range(nb_samples)):
        res = interface({"msg": "request"})
        if "ciphertext" in res.keys():
            otps.append(list(base64.b64decode(res["ciphertext"])))

    flag_bytes = []

    for k in range(len(otps[0])):
        bytes_impossible = list(set(list(map(lambda x:x[k],otps))))
        
        flag_bytes_inter = []
        for i in range(128):
            if i not in bytes_impossible:
                flag_bytes_inter.append(bytes([i]))
        flag_bytes.append(flag_bytes_inter)


    # plutôt que d'afficher un flag quand on est certain 
    # on va afficher les flags possibles à l'instant donné
    flags = []
    for i, bytes_ in enumerate(flag_bytes):
        flag_inter = []
        flag_copy = flags.copy()
        for index, byte in enumerate(bytes_):
            if i==0:
                flag_inter.append(byte)
            else:
                flag_inter =  flag_inter + list(map(lambda x:x + byte , flag_copy))

        flags = flag_inter

    flags = [k for k in flags if b"crypto{" in k and k[-1]==125]
    flags = sorted(flags)
    return flags


if __name__ == "__main__":
    #============= Local ============
    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flags = resolve_challenge(interface_)
    print(flags)
    assert FLAG.encode() in flags

    #============= Cryptohack ============

    r.readline()
    interface_ = interface
    flags = resolve_challenge(interface_)
    print(flags)
    assert b'crypto{unr4nd0m_07p}' in flags