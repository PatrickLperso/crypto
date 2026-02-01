import random
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
import os


r = remote('socket.cryptohack.org', 13426, level = 'info')

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


FLAG = b"crypto{??????????????????????}"

padded_flag = FLAG + os.urandom(q.bit_length() // 8 - len(FLAG) - 2)
flag = bytes_to_long(padded_flag)

y = pow(g,flag,p)

class Challenge:
    def __init__(self):
        self.before_input = f"I will prove to you that I know flag `w` such that y = g^w mod p.\n"
        self.state = "CHALLENGE1"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE1":
            # Prover sends a randomly sampled `A` value from Z_P* to verifier
            self.r = random.randint(0,q)
            self.a = pow(g,self.r,p)
            
            self.state = "PROVE1"
            return {"a": self.a, "y": y, "message": "send random e in range 0 <= e < 2^511"}

        elif self.state == "PROVE1":
            # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
            self.e = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z = (self.r + self.e*flag) % q

            self.state = "CHALLENGE2"
            self.no_prompt = True # immediately send next line
            return {"z": self.z, "message": "not convinced? I'll happily do it again!"}

        elif self.state == "CHALLENGE2":
            # Prover sends a randomly sampled `A` value from Z_P* to verifier
            # self.r = random.randint(0,q) # oh no they reused the same r
            self.a2 = pow(g,self.r,p)
            
            self.state = "PROVE2"
            return {"a2": self.a2, "y": y, "message": "send random e in range 0 <= e < 2^511"}

        elif self.state == "PROVE2":
            # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
            self.e2 = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z2 = (self.r + self.e2*flag) % q

            self.exit = True
            return {"z2": self.z2, "message": "I hope you're convinced I know the flag now. Goodbye :)"}


def witness_extractor(interface, interface_read, p, q, g):

    #  ==== first Verifier sigma interation ==========
    challenge1 = interface_read("toto")
    a, y = challenge1["a"], challenge1["y"]

    e = random.randint(0,q)

    z = interface({"e":e})["z"]

    #  ==== Second Verifier sigma interation ==========
    challenge2 = interface_read("toto")
    a2, y = challenge2["a2"], challenge2["y"]

    e2 = random.randint(0,q)
    z2 = interface({"e":e2})["z2"]

    # ==== Witness extraction ====
    w = ((z-z2)*pow(e-e2,-1, q))%q

    flag = long_to_bytes(w)

    return flag[:flag.index(b"}")+1]

if __name__ == "__main__":

    challenge_ = Challenge()
    interface_= challenge_.challenge
    interface_read_ = interface_
    flag = witness_extractor(interface_, interface_read_, p, q, g)
    assert flag == FLAG

    r.readline()
    interface_ = interface
    interface_read_ = interface_read
    flag = witness_extractor(interface_, interface_read_, p, q, g)
    assert flag == b'crypto{specially_sound_sigmas}'