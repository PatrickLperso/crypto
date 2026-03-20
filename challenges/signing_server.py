from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

from pwn import *
import json

r = remote('socket.cryptohack.org', 13374, level = 'info')

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())


SECRET_MESSAGE = b"crypto{....}"
E = 65537
p = getPrime(1024)
q = getPrime(1024)
N = p*q

phi = (p - 1) * (q - 1)
D = inverse(E, phi)

class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my signing server. You can get_pubkey, get_secret, or sign.\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_pubkey':
            return {"N": hex(N), "e": hex(E) }

        elif your_input['option'] == 'get_secret':
            secret = bytes_to_long(SECRET_MESSAGE)
            return {"secret": hex(pow(secret, E, N)) }

        elif your_input['option'] == 'sign':
            msg = int(your_input['msg'], 16)
            return {"signature": hex(pow(msg, D, N)) }

        else:
            return {"error": "Invalid option"}


def recover(interface):

    secret_cipher = interface({'option':'get_secret'})["secret"]

    secret =  interface({'option':'sign', "msg": secret_cipher})["signature"]
    return bytes.fromhex(secret[2:])

if __name__ == "__main__":
    # ===== local =====
    challenge = Challenge()
    interface_ = challenge.challenge

    flag = recover(interface_)
    assert flag == SECRET_MESSAGE

    # ===== online =====
    print(r.readline())
    interface_ = interface
    flag = recover(interface_)
    assert flag =="crypto{d0n7_516n_ju57_4ny7h1n6}"

