
from Crypto.Util.number import bytes_to_long, getPrime
import random
from sage.all import PolynomialRing, Zmod, RealField
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse


FLAG = b'crypto{???????????????????????????}'

# ===============================================
# ==================Mes ajouts ==================
# ===============================================
from pwn import *
import json
import string

r = remote('socket.cryptohack.org', 13386, level = 'info')

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

# ===============================================
# ===============================================
# ===============================================


class Challenge():
    def __init__(self):
        self.before_input = "Come back as much as you want! You'll never get my flag.\n"
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.N = self.p * self.q

        # tiens ?
        self.e = 11

    def pad(self, flag):
        m = bytes_to_long(flag)
        a = random.randint(2, self.N)
        b = random.randint(2, self.N)
        return (a, b), a*m+b

    def encrypt(self, flag):
        pad_var, pad_msg = self.pad(flag)
        encrypted = (pow(pad_msg, self.e, self.N), self.N)
        return pad_var, encrypted

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_flag':
            pad_var, encrypted = self.encrypt(FLAG)
            return {"encrypted_flag": encrypted[0], "modulus": encrypted[1], "padding": pad_var}

        else:
            return {"error": "Invalid option"}

def euclide_gcd(f, g):
    while g != 0:
        f, g = g, f % g
    return f.monic()

def recover_franklin_reiter(interface):

    # 2. Convertir N en un réel Sage de haute précision AVANT la puissance
    RR_prec = RealField(2048)
    
    res1 = interface({"option":"get_flag"})
    c1, n, padding1 = res1["encrypted_flag"], res1["modulus"], res1["padding"]
    a1, b1 = padding1

    res2 = interface({"option":"get_flag"})
    c2, n, padding2 = res2["encrypted_flag"], res2["modulus"], res2["padding"]
    a2, b2 = padding2

    R = PolynomialRing(Zmod(n), names=('x'))
    x = R.gen()
    e = 11
    
    f1 = (a1*x + b1)**e - c1
    f2 = (a2*x + b2)**e - c2

    gcd = euclide_gcd(f1, f2)

    # (x - M2) divise les deux polynomes
    flag = long_to_bytes(int(-gcd[0]))
    return flag

if __name__ == "__main__":
    # ===== local =====
    challenge = Challenge()
    interface_ = challenge.challenge

    flag = recover_franklin_reiter(interface_)
    assert flag == FLAG

    # ===== cryptohack =====
    r.readline()
    interface_ = interface

    flag = recover_franklin_reiter(interface_)
    assert flag == b'crypto{linear_padding_isnt_padding}'