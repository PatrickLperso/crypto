from py_ecc.optimized_bn128 import G1, G2, multiply, pairing, is_on_curve, b, FQ
from hashlib import sha256
import os

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from os import urandom

from pwn import *
import json

from sage.all import Integer, GF
from itertools import product 
from functools import reduce
from tqdm import tqdm

r = remote('socket.cryptohack.org', 13415)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())


p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
FLAG = b"crypto{???????????????????????????????????????????????????}"

def poly(power, x):
    return (pow(x,power+7,p) - pow(x,3,p)) % p # (x**(power+7)-x**3) % p

def inverse(u, v):
    # fonction bizarre, inverse modulaire pété 
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1<0:
        u1 = u1 + v
    return u1

def hash_to_curve(h, G):
    return multiply(G,h)

class Challenge:
    def __init__(self):
        self.before_input = "Welcome! Have fun with this strange implementation...\n"

        # 24 bytes
        self.x = int(os.urandom(192//8).hex(), 16)
        self.z = 17

    def BLS(self, hsh,  G):
        # injection sur G ?

        h = int(sha256(FLAG).hexdigest(),16)
        
        # a checker, ca parait louche
        H = hash_to_curve(h, G2)

        if not is_on_curve(G, b):
            return False
        received_H = hash_to_curve(hsh, G2)
        xH = multiply(H, self.x)
        xG = multiply(G, self.x)
        xzH = multiply(xH, self.z)
        xzG = multiply(xG, self.z)
        l = pairing(xzH, G1)
        r = pairing(received_H, xzG)
        
        # pairing(xzH, G1) == pairing(received_H, xzG)
        
        # xH = multiply(G, self.x)
        # xG = multiply(G, self.x)

        # self.z injectable
        # hsh injectable
        # G injectable, G appartient à G1
        # pairing(multiply(multiply(hash_to_curve(h, G2), self.x), self.z), G1) 

        # pairing(G1, self.z*self.x*h*G2) = pairing(G1,G2)^(self.z*self.x*h)

        # pairing(multiply(G2, hsh), multiply(multiply(G, self.x), self.z))
        # G = nG1
        # pairing(self.z*self.x*G, hsh*G2) = pairing(G1,G2)^(n*self.z*self.x*hsh)
        # ce qui implique donc 

        # n*self.z*self.x*hsh = self.z*self.x*h (modulo smtgh?)
        # n*hsh = h

        # pairing(G1, self.z*self.x*h*G2) = pairing(self.z*self.x*n*G1, hsh*G2)
        return l == r

    def set_internal_z(self, z):
        # z = (poly(z, self.x)^-1)mod p
        # z = (self.x**(z+7)-self.x**3)^-1 % p


        z = inverse(poly(z, self.x), p)
        if (self.x*z) % p == 1:
            raise Exception("Wtf?")
        self.z = z

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        if your_input["option"] == "set_internal_z":
            try:
                new_z = int(your_input["z"],16)
                if not 0 < new_z < p:
                    return {"error": "this is a mandatory: 0 < z < p"}
                self.set_internal_z(new_z)
            except Exception as e:
                return {"error": str(e)}
            return {"msg": "Internal z changed!"}

        elif your_input["option"] == "do_proof":
            try:
                G = your_input["G"].replace("(","").replace(")","").strip().split(",")
                G = (FQ(int(G[0])), FQ(int(G[1])), FQ(int(G[2])))
                hsh =  int(your_input["hsh"], 16)
                if self.BLS(hsh, G):
                    return {"msg":FLAG.decode()}
                else:
                    return {"msg": "you failed!"}
            
            # intriguant qu'on puisse lire les erreurs
            except Exception as e:
                import traceback
                print(traceback.format_exc())
                return {"error": str(e)}
        else:
            return {"error": "Invalid option"}


def resolve_challenge(interface, z_test):

    interface({"option":"set_internal_z", "z": z_test })
    res = interface({"option":"do_proof", "hsh": long_to_bytes(1).hex(),"G":"(1,2,1)" })
    return res["msg"]
    # On cherche à résoudre :
    # G = n*G1
    # pairing(G1, self.z*self.x*h*G2) = pairing(self.z*self.x*n*G1, hsh*G2)
    # si on arrive à injecter 0 de chaque coté, on se libère de la contrainte sur h le hash du flag
    # que l'on ne connait pas 

    # Or on peut injecter
    # self.z
    #   - il y a des checks
    #   - self.z = inverse(poly(z, self.x), p) or inverse est mal codé car inverse(0,p)=0 
    # Donc si poly(z, self.x) ==0 mod p on est bon 
    # or poly(z, self.x) ==0 mod p <=> x**(power+7) - x**3 % p ==0 <=> x**3(x**power+4-1)%p ==0
    # si on enleve la solution triviale x**3=0 
    # x**power+4-1 ==0 mod p  donc x**(power+4)==1 mod p 
    # donc le problème revient à trouver l'ordre de x (qui est inconnu) dans GF(p)
    # mais pas besoin de connaitre l'ordre exactement, il suffit d'envoyer l'ordre du groupe multiplicatif

    # En particulier 
    #   - G doit être sur la curve
    # hsh 
    #   - aucun check

if __name__ == "__main__":


    challenge_ = Challenge()
    interface_ = challenge_.challenge

    # ============== Demo principle of attack ==========
    F = GF(p)
    z_test = hex(F(challenge_.x).multiplicative_order()-4)

    flag = resolve_challenge(interface_, hex(p-1-4))
    assert flag == FLAG.decode()

    # ============== Attack ==========
    r.readline()
    interface_ = interface
    flag = resolve_challenge(interface_, hex(p-1-4))
    assert flag == "crypto{don_t_let_useless_param_and_edge_cases_in_your_code}"
