import numpy as np
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import math
from sympy import gcd
from tqdm import tqdm

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import random
import math

def generate_vulnerable_keys(count=50, shared_pool_size=5):
    # généré par gemini pour tester
    """
    Génère 'count' clés RSA. Certaines partageront des facteurs communs.
    """
    keys = []
    
    # 1. On génère un pool de nombres premiers "communs"
    # Pour simplifier, on génère des clés et on en extrait un p
    shared_primes = []
    print(f"--- Génération du pool de {shared_pool_size} premiers partagés ---")
    for _ in range(shared_pool_size):
        tmp_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        p = tmp_key.private_numbers().p
        shared_primes.append(p)

    print(f"--- Génération de {count} clés RSA ---")
    for i in range(count):
        # On décide si cette clé sera "infectée" (50% de chance)
        if random.choice([True, False]):
            p = random.choice(shared_primes)
            # On doit générer un q unique pour que N soit différent
            # Note: En pratique, on génère une clé normale et on remplace p
            q = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_numbers().p
            
            # Reconstruction manuelle de la clé avec le p partagé
            n = p * q
            # On simplifie ici en stockant juste (n, e) pour ton attaque
            keys.append({"id": i, "n": n, "e": 65537, "vulnerable": True})
        else:
            # Clé parfaitement saine
            key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
            keys.append({"id": i, "n": key.public_key().public_numbers().n, "e": 65537, "vulnerable": False})
            
    return keys

def factor(modulos):
    factorisation = list(zip(len(modulos)*[1],modulos))

    # under certains constraints it's possible that devices generate the same prime factors
    # note that for large scale scrapping, it's possible to optimize the euclidian algorithm  
    # https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final228.pdf
    # https://eprint.iacr.org/2012/064.pdf
    
    for i in tqdm(range(len(modulos))):
        for j in range(i):
            # the two shares a common factors
            gcd_ = gcd(modulos[i],modulos[j])
            if gcd_!=1:
                if factorisation[i][0]==1:
                    factorisation[i] = [modulos[i]//gcd_,gcd_]
                if factorisation[j][0]==1:
                    factorisation[j] = [modulos[j]//gcd_,gcd_]

    return factorisation



if __name__ == "__main__":
    
    keys = generate_vulnerable_keys(50)

    factorisation = factor(list(map(lambda x:x["n"],keys)))

    print("toto")