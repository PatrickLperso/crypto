from hashlib import sha256
import os

from pwn import *
import json

r = remote('socket.cryptohack.org', 13402)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG = b"crypto{???????????????????????????????}"


def _xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def _and(a, b):
    return bytes([_a & _b for _a, _b in zip(a, b)])

def shuffle(mixed_and, mixed_xor):
    return bytes([mixed_xor[i%len(mixed_xor)] for i in mixed_and])


class Challenge():
    def __init__(self):
        self.before_input = "Oh no, how are you going to unmix this?\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "mix":
            if not "data" in msg:
                return {"error": "Please send hex-encoded data"}

            data = bytes.fromhex(msg["data"])
            if len(data) < len(FLAG):
                data += os.urandom(len(FLAG) - len(data))

            mixed_and = _and(FLAG, data)
            mixed_xor = _xor(_xor(FLAG, data), os.urandom(len(FLAG)))

            very_mixed = shuffle(mixed_and, mixed_xor)
            super_mixed = sha256(very_mixed).hexdigest()

            return {"mixed": super_mixed}

        else:
            return {"error": "Invalid option"}

def resolve_challenge(interface):
    res = interface({"option":"mix", "data":1})
    


if __name__ == "__main__":

    #============= Local ============
    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = resolve_challenge(interface_)
    assert flag == FLAG

    #============= Cryptohack ============

    #r.readline()
