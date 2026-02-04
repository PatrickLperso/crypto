import random
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
import os


r = remote('socket.cryptohack.org', 13427, level = 'info')

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

def interface_read(msg):
    # on envoie la requete 
    # l'argument useless est pour utiliser l'interface local qui nécessité un message 
    line = r.readline()
    return json.loads(line.decode())

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

FLAG = b"crypto{?????????????????????????????}"

padded_flag = FLAG + os.urandom(q.bit_length() // 8 - len(FLAG) - 1)
flag = bytes_to_long(padded_flag)

y = pow(g,flag,p)

assert (y%p) >= 1
assert pow(y, q, p) == 1


class Challenge:
    def __init__(self):
        self.before_input = f"Send me a transcript for my given `e` proving that you know the flag `w` such that y = g^w mod p\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            self.e = random.randint(0,2**511)
            
            self.state = "PROVE"
            return {"e": self.e, "y": y, "message": "send me your transcript"}

        elif self.state == "PROVE":
            self.a = msg["a"]
            self.z = msg["z"]

            if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                self.exit = True
                return {"error": "Invalid value"}

            self.exit = True

            # Verifier checks g^z = A*h^e mod p
            if pow(g,self.z,p) == (self.a*pow(y,self.e,p)) % p:
                return {"flag": FLAG.decode(), "message": "You convinced me you know an `w` such that g^w = y mod p!"}
            else:
                return {"error": "something went wrong :("}

def witness_extractor(interface, interface_read, p, q, g):

    #  ==== get e and y ==========
    challenge = interface_read("toto")
    e, y = challenge["e"], challenge["y"]

    #  ==== craft malicious a ==========
    z = random.randint(0,q)
    a = pow(g, z, p)*pow(y, -e, p)
    flag = interface({"a":a, "z":z})["flag"]

    return flag

if __name__ == "__main__":

    challenge_ = Challenge()
    interface_= challenge_.challenge
    interface_read_ = interface_
    flag = witness_extractor(interface_, interface_read_, p, q, g)
    assert flag == FLAG.decode()

    r.readline()
    interface_ = interface
    interface_read_ = interface_read
    flag = witness_extractor(interface_, interface_read_, p, q, g)
    assert flag == "crypto{so_honest_very_zero_knowledge}"