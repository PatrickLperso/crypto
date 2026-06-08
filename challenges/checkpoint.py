

# Ajout du répertoire eliptic curve
import os, sys

from pwn import *
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from from crypto_core.invalid_curve_attack import generate_invalid_curves, bruteforce_aes, bruteforce_sign_crt, key_uncipher

import logging
logging.basicConfig(level=logging.INFO)

r = remote('socket.cryptohack.org', 13419, level = 'info')

def parse_data(initial_data, curve:WeierStrass):
    get_lines = initial_data.decode().split("\n")[2:-1]
    Point_client_server_x, Point_client_server_y = tuple(map(lambda x:int(x), get_lines[0].split(" : ")[1].strip('Point(x=').strip(")").split(", y=")))
    Point_client_server = PointWeirstrass(curve, Point_client_server_x, Point_client_server_y)

    Point_server_client_x, Point_server_client_y = tuple(map(lambda x:int(x), get_lines[1].split(" : ")[1].strip('Point(x=').strip(")").split(", y=")))
    Point_server_client = PointWeirstrass(curve, Point_server_client_x, Point_server_client_y)

    flag_AES = initial_data.decode().split("\n")[2:-1][2].split(" : ")[1]
    return Point_client_server, Point_server_client, flag_AES


def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

if __name__ == "__main__":
   # NIST P-256

    # ================== Courbe et paramètre  ===============
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    order = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    curve = WeierStrass(a,b,p)
    G = PointWeirstrass(curve, 48439561293906451759052585252797914202762949526041747995844080717082404635286,36134250956749795798585127919587881956611106672985015071877198253568414405109)

    # ======================== initialsation du challenge ======================

    initial_data = r.recv(timeout=0.5)

    Point_client_server, Point_server_client, flag_AES = parse_data(initial_data, curve)

    # ================== Génération des courbes vulnérables ===============

    # on une limite min pour ne pas avoir à bruteforce un système CRT trop complexe à la fin (on aura toujours k ou -k possible)
    # donc éliminer les nombres premiers trop petits permet de s'assurer que le brutefroce du CRT à la fin ne sera pas trop gourmand 
    # si 15 nombre premiers 2**15 systmes du CRT possibles si 20 2**20 etc ..
    primes_curves, b_primes=generate_invalid_curves(a,p,order,min_order_bruteforce=5000, max_order_bruteforce=5000000, bmax=50)
    
    # ================== Bruteforce des sous groupes et attaque sur ECDH ===============
    message_uncipher = b"SERVER_TEST_MESSAGE"
    crt_system_equations = bruteforce_aes(b_primes, primes_curves, message_uncipher, interface=interface)

    # ================== Bruteforce des signes du système d'équations ===============
    solution = bruteforce_sign_crt(crt_system_equations, G, message_uncipher, order, interface=interface)
    logging.info(f"solution:{solution}")

    # ================== Récupération du flag ===============
    cipher = bytes.fromhex(flag_AES)
    iv = cipher[:16]
    message_cipher = cipher[16:]
    
    flag = unpad(key_uncipher(solution, Point_client_server, iv, message_cipher),16)
    logging.info(flag)
    assert flag == b'crypto{nice_forward_secrecy_you_have_there!}'