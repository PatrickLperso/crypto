
# Ajout du répertoire eliptic curve
import os, sys
import json
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

from tqdm import tqdm
import gmpy2
from Crypto.Util.number import getPrime, isPrime
from functools import reduce

import logging
logging.basicConfig(level=logging.INFO)

from deriving_symetric_keys import decrypt_flag 

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from Polhig_Hellman_DL import polhig_hellman, order_g_f
from sage.all import Integer

# from cysignals.alarm import alarm, AlarmInterrupt, cancel_alarm

def interface(r, data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

def send_data(r, data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(re.search("{.*", line.decode(), re.DOTALL)[0])

def read_data(r):
    line = r.readline()
    return json.loads(re.search("{.*", line.decode(), re.DOTALL)[0])    


def send_weak_modulo(p_inject):
    r = remote('socket.cryptohack.org', 13378, level = 'debug')

    alice_data = read_data(r)
    bob_data = read_data(r)

    A = int(alice_data["A"],16)
    g = int(alice_data["g"],16)
    p = int(alice_data["p"],16)

    B = int(bob_data["B"],16)

    alice_iv_cipher = read_data(r)
    iv_flag = alice_iv_cipher["iv"]
    cipher_flag = alice_iv_cipher["encrypted"]

    # injection dans la payload
    payload = {"p":long_to_bytes(p_inject).hex(), "g":long_to_bytes(g).hex(), "A":long_to_bytes(A).hex()}
    assert len(json.dumps(payload).encode()) < 1024 
    bob_data_mitm = send_data(r, payload)
    
    r.close()

    return int(bob_data_mitm["B"],16)

def smooth_p(g, p):
    # je ne comprends pas comment on était censé pensé spécifiquement à ça mais bon 
    # sinon très difiicle de trouver dans un temps raisonnable un p avec len(bin(p))-2 > 1500 ..
    # tout en étant très friable et premier
    # le fait que il faut avoir la chance que g ne soit pas dans un sous groupe trop petit

    mul = 1
    i = 1
    while 1:
        mul *= i
        if (mul + 1).bit_length() >= p.bit_length() and isPrime(mul + 1):
            return mul + 1
        i += 1

if __name__ == "__main__":

    r = remote('socket.cryptohack.org', 13378, level = 'debug')

    alice_data = read_data(r)
    bob_data = read_data(r)

    A = int(alice_data["A"],16)
    g = int(alice_data["g"],16)
    p = int(alice_data["p"],16)

    B = int(bob_data["B"],16)

    alice_iv_cipher = read_data(r)
    iv_flag = alice_iv_cipher["iv"]
    cipher_flag = alice_iv_cipher["encrypted"]

    r.close()

    p_inject = smooth_p(g, p)

    order_prime_decomposition = list(Integer(p_inject-1).factor())

    # we need to ebnsure that the order of g is above the order p-1 of the legitmate curve
    # becauser B = g^[b%ord(g)] mod p_inject
    order_prime_decomposition_g, order_g = order_g_f(g, p_inject, order_prime_decomposition)
    assert order_g > p - 1

    B_inject = send_weak_modulo(p_inject)

    res = polhig_hellman(B_inject, g, p_inject, True, order_prime_decomposition, order_prime_decomposition_g)
    assert pow(g, res[0], p) == B

    shared_secret = pow(A, res[0], p)
    flag = decrypt_flag(shared_secret, iv_flag, cipher_flag)
    assert flag == "crypto{uns4f3_pr1m3_sm4ll_oRd3r}"