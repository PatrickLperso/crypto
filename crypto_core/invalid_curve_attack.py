
import logging
from tqdm import tqdm
from functools import reduce
import math 
import json
from typing import List, Tuple
from itertools import product 
import logging

from os import urandom
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

from sage.all import EllipticCurve, GF
from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from crypto_core.modular_arithmetic import ChineseRemainder

logging.basicConfig(level=logging.INFO)
# ===== Interfaces well defined  =========

FLAG = b"crypto{????????????????????????????????????}"

class Server:
    def __init__(self, curve:WeierStrass, G:PointWeirstrass):
        self.curve = curve
        assert G.curve==self.curve
        self.G = G

        self.secret = int.from_bytes(urandom(32), byteorder="little")
        self.public_key = self.secret*G

    def ecdh_kex(self, Q, ciphersuite):
        if ciphersuite != "ECDHE_P256_WITH_AES_128":
            raise Exception("Ciphersuite not supported.")
        shared_point = self.secret * Q
        self.shared_key = sha256(str(shared_point.x).encode()).digest()[:16]

    def send_msg(self, message):
        iv = urandom(16)
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(message, 16))


class Challenge:
    def __init__(self, curve:WeierStrass, G:PointWeirstrass):
        self.server = Server(curve, G)
        client_secret_key = int.from_bytes(urandom(32), byteorder="little")
        self.client_public_key = client_secret_key * G
        self.server.ecdh_kex(self.client_public_key, "ECDHE_P256_WITH_AES_128")
        self.before_input = (
            f"Eavesdropping...\n"
            f"client initiating key agreement :\n"
            f"client->server : {self.client_public_key}\n"
            f"server->client : {self.server.public_key}\n"
            f"server->client : {self.server.send_msg(FLAG).hex()}\n"
        )

    def challenge(self, your_input):
        if your_input["option"] == "start_key_exchange":
            if "Qx" not in your_input or "Qy" not in your_input:
                return {"msg": "No public key provided."}
            if "ciphersuite" not in your_input:
                return {"msg": "No ciphersuite provided"}
            try:
                # La vulnérabilité de ne pas vérifier si le point Q est sur la courbe 
                Q = PointWeirstrass(self.server.curve, int(your_input["Qx"], 16), int(your_input["Qy"], 16), secure=False)
                self.server.ecdh_kex(Q, your_input["ciphersuite"])
            except:
                return {"msg": "An error occured, please provide valid inputs."}
            return {"msg": "Key exchange proceeded successfully."}

        if your_input["option"] == "get_test_message":
            return {"msg": self.server.send_msg(b"SERVER_TEST_MESSAGE").hex()}

def key_exchange_attack(G:PointWeirstrass, interface):
    input_key_exchange = {
        'option':'start_key_exchange',
        'ciphersuite':'ECDHE_P256_WITH_AES_128',
        'Qx':hex(G.x),
        'Qy':hex(G.y),
    }

    res_server = interface(input_key_exchange)
    assert res_server == {"msg": "Key exchange proceeded successfully."}

    input_key_exchange = {
    'option':'get_test_message',
    }

    cipher = bytes.fromhex(interface(input_key_exchange)["msg"])
    iv = cipher[:16]
    message_cipher = cipher[16:]
    return iv, message_cipher

def key_uncipher(key:int, Q:PointWeirstrass, iv:bytes, message_cipher:bytes):
    shared_point = key * Q
    shared_key = sha256(str(shared_point.x).encode()).digest()[:16]
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    plaintext_unpad = cipher.decrypt(message_cipher)
    return plaintext_unpad

def generate_invalid_curves(a:int,p:int,order:int,min_order_bruteforce:int, max_order_bruteforce:int=100000, bmax:int=50):

    primes_curves={}
    b_primes={}
    
    progress_bar_last_value=0
    max_value=256
    progress_bar = tqdm(total=max_value)

    for b in range(bmax):
        if -16 * (4 * a**3 + 27 * b**2) %p!=0: # on veut pas de courbes singulières
            E  = EllipticCurve(GF(p), [a, b])
            G = E.gens()
            curve_weirstrass = WeierStrass(a, b, p)
            G = PointWeirstrass(curve_weirstrass, int(tuple(G[0])[0]), int(tuple(G[0])[1]))
            
            order = E.order()
            prime_decomposition = order.factor()
            prime_decomposition =  [(int(k[0]),int(k[1])) for k in list(prime_decomposition)]

            list_prime_inter=[]

            for prime, power in prime_decomposition:
                if min_order_bruteforce<prime**power<max_order_bruteforce :
                    if prime not in primes_curves.keys():
                        primes_curves[prime]={"b":b, "power":power}
                        list_prime_inter.append(prime)
                    else:
                        # c'est arbitraire  
                        if primes_curves[prime]["power"]<power:
                            b_primes[primes_curves[prime]["b"]]["list_prime"].remove(prime)
                            b_primes[primes_curves[prime]["b"]]["list_prime_avoid"].append(prime)
                            primes_curves[prime]={"b":b, "power":power}
                            list_prime_inter.append(prime)
                

            if len(list_prime_inter)!=0:
                list_prime_avoid = [k[0] for k in prime_decomposition if k[0] not in list_prime_inter]
                b_primes[b] = {
                                "curve":curve_weirstrass,
                                "G":G,
                                "a":a,
                                "p":p,
                                "order": int(order),
                                "prime_decomposition":prime_decomposition,
                                "list_prime_avoid": list_prime_avoid,
                                "list_prime":list_prime_inter
                                }
            
            power_product=1
            for prime in primes_curves.keys():
                power_product *= prime ** primes_curves[prime]["power"]
            #logging.info(f"power_product:2**{math.log2(power_product):.1f}, target:2**{math.log2(order):.1f}, nb_primes:{len(primes_curves.keys())}")

            if progress_bar_last_value != math.log2(power_product):
                progress_bar.update(min(max_value - progress_bar_last_value, math.log2(power_product) - progress_bar_last_value))
                progress_bar_last_value=math.log2(power_product)

            if power_product > order:
                logging.info(f"Number of primes (and server exchange) :{len(primes_curves.keys())}")
                logging.info(f"Number of AES calculation needed :{(reduce(lambda x,y:x+y, list(primes_curves.keys())))//2}")
                break

    if power_product < order:
        raise Exception("Insufficent number of curves produced to break the curve")

    return primes_curves,b_primes

def bruteforce_key(iv:bytes, message_cipher:bytes, message_uncipher:bytes, Q:PointWeirstrass, order_subgroup:int):

    # on ne fait que 1 à (order+1)//2 parce qu'on ne cherche que k mod order_subgroup ou -k mod order_subgroup
    for key_candidate in tqdm(range(1,(order_subgroup+1)//2)):
        if key_uncipher(key_candidate, Q, iv, message_cipher).startswith(message_uncipher):
            return key_candidate
    raise Exception("something wrong")


def bruteforce_aes(b_primes:dict, primes_curves:dict,message_uncipher:bytes, interface):
    crt_system_equations=[]
    bit_info = 0
    for b, b_curve in b_primes.items():
        curve = b_curve["curve"]
        G = b_curve["G"]
        order = b_curve["order"]
        list_prime = b_curve["list_prime"]
        for prime in list_prime:
            
            # Génération du point dans notre sous groupe vulnérable (c'est à dire dordre p_i**e_i)
            order_subgroup = prime**primes_curves[prime]["power"]
            Q = (order//order_subgroup) * G

            # logs
            if len(crt_system_equations)!=0:
                bit_info = math.log2(reduce(lambda x, y: x * y, list(map(lambda x:x[1],crt_system_equations))))
            logging.info(f"p_i:{prime}, order:{order_subgroup}, bit of info : {bit_info}")

            iv, message_cipher = key_exchange_attack(Q, interface)

            key = bruteforce_key(iv, message_cipher, message_uncipher, Q, order_subgroup)
            crt_system_equations.append((key, order_subgroup))

    return crt_system_equations

def bruteforce_sign_crt(crt_system_equations: List[tuple[int,int]], G:PointWeirstrass, message_uncipher, order, interface):
    # apparement il y a moyen de résoudre le CRT sans bruteforcer le 2**n
    # ouep c'est super con en plus il faut mettre au carré et
    # résoudre x**2 = k_i**2 mod p_i
    # quand on a x**2, on peut facilement retrouver x mais cela demande que le produit des facteur premiers soit superieur à 2**512
    # Pas sur que ce soit vraiment ... ca va demander beaucoup plus de calculs pour la partie bruteforce AES
    # https://mathoverflow.net/questions/437758/modular-square-roots-problem-which-is-np-hard/451893#451893
    # Commentaire super interressant dans les solutions (la 1ère)

    iv, message_cipher = key_exchange_attack(G, interface)

    # on a pour chaque sous groupe k ou -k donc on a 2**(nombre de sous groupe) possiblités
    for signs in tqdm(product([1, -1], repeat=len(crt_system_equations)), total=2**len(crt_system_equations)):
        solution, modulo = ChineseRemainder(list(map(lambda x,y:((y*x[0])%x[1],x[1]),crt_system_equations, signs)), True)

        if key_uncipher((solution%order), G, iv, message_cipher).startswith(message_uncipher):
            found = True
            break
    
    # En verité la clé secrète est peut-être (-solution%order) 
    # Mais on s'en fiche car ((-solution%order)*G).x == (solution%order*G).x 
    # Les deux donne la même clé AES
    # on aurait pu tester la coordonneé x du serveur car la clé publique nous est donnée
    print(f"found :{found}")
    return solution%order
        

if __name__ == "__main__":
    # NIST P-256

    # ================== Courbe et paramètre et initalisation du challenge ===============
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    order = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    curve = WeierStrass(a,b,p)
    G = PointWeirstrass(curve, 48439561293906451759052585252797914202762949526041747995844080717082404635286,36134250956749795798585127919587881956611106672985015071877198253568414405109)
    challenge = Challenge(curve, G)

    logging.info(f"private_key: {challenge.server.secret}")

    # ================== Génération des courbes vulnérables ===============
    logging.info(f"\n=============Curves generation ================")
    # on une limite min pour ne pas avoir à bruteforce un système CRT trop complexe à la fin (on aura toujours k ou -k possible)
    # donc éliminer les nombres premiers trop petits permet de s'assurer que le brutefroce du CRT à la fin ne sera pas trop gourmand 
    # si 15 nombre premiers 2**15 systmes du CRT possibles si 20 2**20 etc ..
    primes_curves, b_primes=generate_invalid_curves(a,p,order,min_order_bruteforce=5000, max_order_bruteforce=5000000, bmax=50)
    
    # ================== Bruteforce des sous groupes et attaque sur ECDH ===============
    logging.info(f"\n============= ECDH exchanges and AES bruteforce==============")

    message_uncipher = b"SERVER_TEST_MESSAGE"
    crt_system_equations = bruteforce_aes(b_primes, primes_curves, message_uncipher, interface=challenge.challenge)

    # ================== Bruteforce des signes du système d'équations ===============
    logging.info(f"\n=========== Bruteforce CRT equations system signs ======")
    solution = bruteforce_sign_crt(crt_system_equations, G, message_uncipher, order, interface=challenge.challenge)
    logging.info(f"solution:{solution}")

    # ================== Récupération du flag ===============
    cipher = bytes.fromhex(challenge.before_input.split("\n")[4].split(" : ")[1])
    iv = cipher[:16]
    message_cipher = cipher[16:]
    
    flag = unpad(key_uncipher(solution, challenge.client_public_key, iv, message_cipher),16)
    assert flag == FLAG

