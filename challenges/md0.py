from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

from pwn import *
import json

r = remote('socket.cryptohack.org', 13388)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG = "crypto{???????????????}"


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hash(data):
    data = pad(data, 16)
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out


class Challenge():
    def __init__(self):
        self.before_input = "You'll never forge my signatures!\n"
        self.key = os.urandom(16)

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            data = bytes.fromhex(msg["message"])
            if b"admin=True" in data:
                return {"error": "Unauthorized to sign message"}
            sig = hash(self.key + data)

            return {"signature": sig.hex()}

        elif msg["option"] == "get_flag":
            sent_sig = bytes.fromhex(msg["signature"])
            data = bytes.fromhex(msg["message"])
            real_sig = hash(self.key + data)

            if real_sig != sent_sig:
                return {"error": "Invalid signature"}

            if b"admin=True" in data:
                return {"flag": FLAG}
            else:
                return {"error": "Unauthorized to get flag"}

        else:
            return {"error": "Invalid option"}


def resolve_challenge(interface):
    # hash(self.key + data + padding)

    message_to_sign = os.urandom(16)
    signature= bytes.fromhex(interface({"option":"sign", "message": message_to_sign.hex() })["signature"])

    # faire attnetion le message est paddé pour la signature 
    # la clé fait 16 octet donc message_to_sign + key fait 32 octet 
    # et ond cun padding d'un bloc complet de bytes([16]*16) est ajouté
    # le truc est simple car on connait la taille de clé
    # pas besoin de bruteforce les padding possible

    injection = b"admin=True"
    new_data = pad(injection, 16)
    signature_ext = bxor(AES.new(new_data, AES.MODE_ECB).encrypt(signature), signature)


    message = message_to_sign + bytes([16]*16) + injection
    res = interface({"option":"get_flag", "message":message.hex(), "signature": signature_ext.hex() })["flag"]

    return res

if __name__ == "__main__":

    # =========== local ===========

    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = resolve_challenge(interface_)
    assert flag == FLAG

    # =========== cryptohack ===========
    r.readline()
    interface_ = interface
    flag = resolve_challenge(interface_)
    assert flag == "crypto{l3ngth_3xT3nd3r}"