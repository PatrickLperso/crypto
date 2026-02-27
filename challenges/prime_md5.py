from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime, getPrime, GCD
import math
from sympy import factorint
# from secrets import N, E, D
from tqdm import tqdm

import os, sys
from pwn import *
import json
import subprocess

r = remote('socket.cryptohack.org', 13392)


def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG = "crypto{??????????????????}"

# Génère une clé RSA de 2048 bits
key = RSA.generate(2048)

# Récupérer N, E, D
N = key.n  # modulus
E = key.e  # exponent public
D = key.d  # exponent privé

print("N =", N)
print("E =", E)
print("D =", D)
# est ce que c'est correct ici ?
key = RSA.construct((N, E, D))
sig_scheme = pkcs1_15.new(key)


class Challenge():
    def __init__(self):
        self.before_input = "Primality checking is expensive so I made a service that signs primes, allowing anyone to quickly check if a number is prime\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            p = int(msg["prime"])
            if p.bit_length() > 1024:
                return {"error": "The prime is too large."}
            if not isPrime(p):
                return {"error": "You must specify a prime."}
            
            # a quoi correspond le hash ici ?
            # on initialise mais on a aucune idée si on prend le digest ou non ?
            hash = MD5.new(long_to_bytes(p))
            sig = sig_scheme.sign(hash)
            return {"signature": sig.hex()}

        elif msg["option"] == "check":
            p = int(msg["prime"])
            sig = bytes.fromhex(msg["signature"])
            hash = MD5.new(long_to_bytes(p))
            try:
                sig_scheme.verify(hash, sig)
            except ValueError:
                return {"error": "Invalid signature."}

            a = int(msg["a"])
            if a < 1:
                return {"error": "`a` value invalid"}
            if a >= p:
                return {"error": "`a` value too large"}
            g = math.gcd(a, p)
            flag_byte = FLAG[:g]
            return {"msg": f"Valid signature. First byte of flag: {flag_byte}"}

        else:
            return {"error": "Unknown option."}

def find_collision(folder_tries):
    # on trouve la collision en realisant plien de collision jusqu'à en trouver une qui soit 
    # un nombre premier sous forme d'octet

    fastcoll_exe = os.path.join(os.path.join(folder, "fastcoll", "fastcoll"))

    for _ in tqdm(range(2000)):
        collision_v1 = os.urandom(128)

        collision_v1_hash = MD5.new(collision_v1).hexdigest()

        collision_v1_hash_file = os.path.join(folder_tries, f"{collision_v1_hash}_v1.txt")
        collision_v2_hash_file = os.path.join(folder_tries, f"{collision_v1_hash}_v2.txt")

        with open(collision_v1_hash_file, "wb") as file:
            file.write(collision_v1)

        subprocess.run([fastcoll_exe, "-o", collision_v1_hash_file, collision_v2_hash_file], check=True)
        
        files = [collision_v1_hash_file, collision_v2_hash_file]
        for index, file in enumerate(files):
            with open(file, "rb") as f:
                data_prime = f.read()

            if isPrime(bytes_to_long(data_prime)):
                prime = bytes_to_long(data_prime)
                
                with open(files[index ^ 1], "rb") as f:
                    data_not_prime = f.read()
                    print(collision_v1_hash_file, collision_v2_hash_file)
                    return data_prime, data_not_prime
            

def resolve_challenge(interface):
    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    folder_tries = os.path.join(folder, "tries")

    # les fichiers ont été obetnus en réalisant des collisions
    # find_collision(folder_tries) 
    collision_prime_filepath = os.path.join(folder_tries,'bca3166e161b97de0a247a2667f2842f_v2.txt')
    collision_not_prime_filepath = os.path.join(folder_tries, 'bca3166e161b97de0a247a2667f2842f_v1.txt')
    
    with open(collision_prime_filepath, "rb") as f:
        data_prime = f.read()

    with open(collision_not_prime_filepath, "rb") as f:
        data_not_prime = f.read()

    
    prime = bytes_to_long(data_prime)
    not_prime = bytes_to_long(data_not_prime)
    assert isPrime(prime)
    assert not isPrime(not_prime)

    res = interface({"option":"sign", "prime": str(prime)})
    signature = res["signature"]

    factorisation = factorint(not_prime, limit = 1000)
    for factor in list(factorisation.keys()):
        if factor>70:
            a = factor  
            break

    flag = interface({"option":"check", "prime": str(not_prime), "signature":signature, "a":str(a)})
    
    return flag["msg"].split(" ")[-1]


if __name__ == "__main__":
    #============= Local ============
    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = resolve_challenge(interface_)
    print(flag)
    assert flag == FLAG

    #============= Cryptohack ============

    r.readline()
    interface_ = interface
    flag = resolve_challenge(interface_)
    assert flag == "crypto{MD5_5uck5_p4rt_tw0}"