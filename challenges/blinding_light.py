#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse

# ===============================================
# ==================Mes ajouts ==================
# ===============================================
from pwn import *
import json
import string

r = remote('socket.cryptohack.org', 13376, level = 'info')

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


FLAG = "crypto{?????????????????????????????}"
ADMIN_TOKEN = b"admin=True"


class Challenge():
    def __init__(self):
        self.before_input = "Watch out for the Blinding Light\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_pubkey':
            return {"N": hex(N), "e": hex(E) }

        elif your_input['option'] == 'sign':
            msg_b = bytes.fromhex(your_input['msg'])
            if ADMIN_TOKEN in msg_b:
                return {"error": "You cannot sign an admin token"}

            msg_i = bytes_to_long(msg_b)
            return {"msg": your_input['msg'], "signature": hex(pow(msg_i, D, N)) }

        elif your_input['option'] == 'verify':
            msg_b = bytes.fromhex(your_input['msg'])
            msg_i = bytes_to_long(msg_b)
            signature = int(your_input['signature'], 16)

            if msg_i < 0 or msg_i > N:
                # prevent attack where user submits admin token plus or minus N
                return {"error": "Invalid msg"}

            verified = pow(signature, E, N)
            if msg_i == verified:
                if long_to_bytes(msg_i) == ADMIN_TOKEN:
                    return {"response": FLAG}
                else:
                    return {"response": "Valid signature"}
            else:
                return {"response": "Invalid signature"}

        else:
            return {"error": "Invalid option"}

def recover(interface):

    res = interface({'option':'get_pubkey'})
    N, e = int(res["N"],16), int(res["e"],16)

    blind = 2
    message = b"admin=True"

    message_blinded = long_to_bytes(blind * bytes_to_long(message))

    signature_blinded = int(interface({'option':'sign', "msg":message_blinded.hex()})["signature"],16)
    signature_blind_factor = int(interface({'option':'sign', "msg":long_to_bytes(blind).hex()})["signature"],16)

    signature = (signature_blinded * pow(signature_blind_factor,-1,N))%N

    res = interface({'option':'verify', "msg":message.hex(), "signature":long_to_bytes(signature).hex()})["response"]
    
    return res


if __name__ == "__main__":
    # ===== local =====
    challenge = Challenge()
    interface_ = challenge.challenge

    flag = recover(interface_)
    assert flag == FLAG

    # ===== cryptohack =====
    r.readline()
    interface_ = interface

    flag = recover(interface_)
    assert flag == "crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5}"