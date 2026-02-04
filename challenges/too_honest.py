from hashlib import sha512

import random
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
import os

r = remote('socket.cryptohack.org', 13429, level = 'debug')

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


# RSA group (2024 bits)
# p,q are both strong primes (i.e. of the form 2x+1 for x prime)

#p = REDACTED
#q = REDACTED
#N = p * q
N = 63506177426384102189597350894327047299059434133653566917776601666605133716653510828029111986956978773016660313963972378811186153674164948861199369871734498221215139927864142313488277305751745855210473314367642273303159704466900274761354992859789827863358153922459760984397971477173435625199596782211170294424560686178858124003120741008270927463303483018910205943877584647744143454984243979284973117132536957364157878132874844783228762221620863204335896952103079109039534346621267709606103312376393511653638269034043434410564414042523141936372609708140474052147124354400977541403247799192906955295291389109531010594317

FLAG = b"crypto{???????????????????}"

g = 2

k1 = 512
k2 = 128
S = 2**k1
R = 2**(2*k2+k1)

padded_flag = FLAG + os.urandom(S.bit_length() // 8 - len(FLAG) - 2)
flag = bytes_to_long(padded_flag)

h = pow(g,-flag,N)


class Challenge:
    def __init__(self):
        self.before_input = f"I will prove to you that I know flag `w` such that h = g^-w mod N\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            # Prover sends a randomly sampled `A` value to verifier
            self.r = random.randint(0,R)
            self.u = pow(g,self.r,N)

            self.state = "PROVE"
            return {"h": h, "u": self.u, "message": "Send a random u in range 0 <= u < 2^{k2}"}

        elif self.state == "PROVE":
            # Verifier sends a random challenge sampled from Z_{2^k2}
            self.e = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z = (self.r + self.e*flag)

            self.exit = True 
            return {"z": self.z, "message": "I hope you're convinced I know the flag now. Goodbye :)"}


def resolve_challenge(interface, interface_read, g, R):

    # =========== on recupère u et h mais osef ===========
    res = interface_read_("")

    # ============= malicious e ======================
    # on peut envoyer kR car il faut juste que e soit un multiple de R car
    # z = r +xe (dans N)
    # donc z%R = r + x(kR)%R = r
    # et ainsi (z-r)/kR=x

    e=R
    z = interface({"e":e})["z"]

    r = z%R
    flag = long_to_bytes((z-r)//e)
    return flag[:flag.index(b"}")+1]

if __name__ == "__main__":

    challenge_ = Challenge()
    interface_ = challenge_.challenge
    interface_read_ = challenge_.challenge

    flag = resolve_challenge(interface_, interface_read_, g, R)
    assert flag == FLAG

    r.readline()
    interface_ = interface
    interface_read_ = interface_read
    flag = resolve_challenge(interface_, interface_read_, g, R)
    assert flag == b'crypto{2_hon3st_to_b3_tru3}'

