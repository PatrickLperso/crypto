import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
from pwn import *
from functools import reduce
from operator import xor
from tqdm import tqdm
import json 
import math

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom

# Import statistics Library
import statistics
import scipy
import numpy as np


def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG = 'crypto{?????????????????????????????????????????????????????}'

def Xor(*args):
    return bytes(reduce(xor, t) for t in zip(*args))

rng = SystemRandom()

class Challenge:
    def __init__(self):
        self.before_input = "That last challenge was pretty easy, but I'm positive that this one will be harder!\n"
        self.message = urandom(16).hex()
        self.key = urandom(16)
        self.query_count = 0
        self.max_queries = 12_000

    def update_query_count(self):
        self.query_count += 1
        if self.query_count >= self.max_queries:
            self.exit = True

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return {"ct": (iv+ct).hex()}

    def check_padding(self, ct):
        ct = bytes.fromhex(ct)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)  # does not remove padding
        try:
            unpad(pt, 16)
        except ValueError:
            good = False
        else:
            good = True
        self.update_query_count()
        return {"result": good ^ (rng.random() > 0.4)}

    def check_message(self, message):
        if message != self.message:
            self.exit = True
            return {"error": "incorrect message"}
        return {"flag": FLAG}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, msg):
        if "option" not in msg or msg["option"] not in ("encrypt", "unpad", "check"):
            return {"error": "Option must be one of: encrypt, unpad, check"}

        if msg["option"] == "encrypt": return self.get_ct()
        elif msg["option"] == "unpad": return self.check_padding(msg["ct"])
        elif msg["option"] == "check": return self.check_message(msg["message"])



def pick_byte_v3(interface, ratio, nb_request, target_byte=None):

    proba_seuil = 0.07 # 0.005

    LOG_TRUE  = math.log(0.4 / 0.6)   # result == True
    LOG_FALSE = math.log(0.6 / 0.4)   # result == False

    entropy = math.log(16)
    seuil_entropy = 0.35 #0.3 #0.2

    round = 0
    trys = 0

    while entropy>seuil_entropy:
        indice = round%16

        if round>=7000:
            raise Exception("Fail bitch round")  

        if (round<20*16 or entropy>2 or ratio[indice]["proba"]>= proba_seuil):

            res = interface({"option" : "unpad", "ct":ratio[indice]["cipher"]})["result"]
            ratio[indice]["round"] += 1

            if res:
                ratio[indice]["log_ratio"] +=  LOG_TRUE
            else:
                ratio[indice]["ratio"] += 1 # number of false obtain
                ratio[indice]["log_ratio"] +=  LOG_FALSE

            nb_request+=1

            trys +=1
            if trys>=3000:
                raise Exception("Fail bitch try")

            softmax_ = scipy.special.softmax(list(map(lambda x:x["log_ratio"], ratio)))
            for k in range(len(ratio)):
                ratio[k]["proba"] = softmax_[k]

            entropy = scipy.stats.entropy(softmax_)
        
        round +=1
        # print(entropy, round, trys)

    ratio = sorted(ratio, key=lambda x:x["proba"],reverse=True)
    byte_bruteforce = ratio[0]["byte"]

    if target_byte is not None:
        print(f' target:{target_byte.decode()} {ratio[0]["plaintext_byte"].decode()} {target_byte == ratio[0]["plaintext_byte"]} {trys} {nb_request}')
        if target_byte != ratio[0]["plaintext_byte"]:
            print("Bad prediction")
    else:
        print(f'{trys} {nb_request}')

    return byte_bruteforce, nb_request


def challenge_resolve(interface, target=None):

    nb_request = 0

    data_interface = bytes.fromhex(interface({"option" : "encrypt"})["ct"])
    iv = data_interface[:16]
    cipher_message = data_interface[16:]
    
    plaintext = b""
    alphabet = b"0123456789abcdef"

    for index_bloc in range(0,len(cipher_message), 16):
        # bloc par bloc (AES CBC) on va déchiffrer le message chiffré
        found = b""
        print(f"\n=====================================================")
        print(f"=======================bloc n°{index_bloc//16+1}=======================")
        print(f"=====================================================")
        for i in tqdm(range(1,17)):
            # byte par byte on va déchiffrer la sortie du bloc AES
            
            ratio = []
            for k in range(256):
                
                byte_bruteforce = bytes([k]).hex() 

                # on s'assure que le plaintext engendré par byte_bruteforce est nécessairement une valeur ascii
                # car ct = cipher.encrypt(self.message.encode("ascii"))
                # permet de réduire le nombre de requêtes

                plaintext_byte = Xor(bytes.fromhex(byte_bruteforce), bytes([i]), bytes([(iv + cipher_message)[index_bloc:index_bloc+16][16-i]]))
                if plaintext_byte in alphabet:
                    # on bruteforce le byte jusqu'a trouver le bon padding
                    

                    # Création de l'IV (payload), on met des 0(bytes([0]*(16-i)).hex()) + octets à bruteforcer (bytes_test) + octets découverts (found.hex() )
                    cipher = bytes([0]*(16-i)).hex() + byte_bruteforce + found.hex() 
                    # Ajout du chiffré 
                    cipher += cipher_message[index_bloc:index_bloc+16].hex()
                    # assert i == len(found)-1
                    # on teste si le padding est valide ou non

                    ratio.append({"byte":byte_bruteforce, "plaintext_byte":plaintext_byte, "ratio":0, "round":0, "log_ratio":0, "proba":1,"p_value_04":None, "p_value_06":None, "diff":0, "cipher": cipher})

            if target is not None:
                target_byte = bytes([target[index_bloc:index_bloc+16][16-i]])
                byte_bruteforce, nb_request = pick_byte_v3(interface, ratio, nb_request, target_byte)
            else:
                byte_bruteforce, nb_request = pick_byte_v3(interface, ratio, nb_request)

            if i!=16:
                found = Xor(bytes.fromhex(byte_bruteforce) + found, bytes([i] * i), bytes([i+1] * i))
            else:
                found = bytes.fromhex(byte_bruteforce)+found

        
        """
        si :
        found XOR AES(cipher) =  10101010101010101010101010101010
        alors :
        AES(cipher) =  found XOR 10101010101010101010101010101010
        """
        output_decryption = Xor(found, bytes([0x10] * 16))

        # on xor la sortie déchiffré des données du bloc AES avec l'iv ou le bloc précédant pour retrouver le plaintext
        # note la disjonction IV et cipher_message pour être enlevée dans le code 
        # on ajoute le plaintext déchiffré au plaintext précédemment trouvé 
        if index_bloc==0:
            plaintext += Xor(output_decryption, iv)
        else:
            plaintext += Xor(output_decryption, cipher_message[index_bloc-16:index_bloc])

    if target is not None:
        comparaison = list(a==b for a,b in zip(plaintext, target))
    print(plaintext.decode())

    try:
        flag = interface({"option" : "check", "message":plaintext.decode()})["flag"] #["flag"]
    except:
        raise Exception

    if target is not None:
        res = flag, nb_request, sum(comparaison), comparaison
    else:
        flag, nb_request

    return flag, nb_request

def log_line(path, line):
    with open("success.txt", "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()


if __name__ == "__main__":
    """
    un peu de doc
    - https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/
    - https://www.brunorochamoura.com/posts/cbc-padding-oracle/
    """
    # test_statistique(200, proba_false_after_true=0.6)

    # # ================ Home test ==================

    # A implenter pour ma propre solution
    # https://www.nccgroup.com/research-blog/exploiting-noisy-oracles-with-bayesian-inference/
    
    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    logfile_path = os.path.join(folder, "log.txt")


    logfile = open(logfile_path, "a", encoding="utf-8")

    nb_mistake=[]
    
    for index_test in range(100):
        try:
            print(f"\nexperience n°{index_test}")
            challenge_ = Challenge()
            interface_ = challenge_.challenge

            target = challenge_.message.encode("ascii")

            #flag = challenge_resolve(interface_, target)
            res = challenge_resolve(interface_)
            logfile.write(f"{res[0]},{res[1]}\n")
            logfile.flush()
            print(res[0])
            nb_mistake.append(res)
        except:
            print(f"\n======================================================================")
            print(f"======================= Abandon nique sa mère =========================")
            print(f"=======================================================================")
            nb_mistake.append(["fail"])
    


    # nb_mistake=[]
    
    # for index_test in range(100):
    #     try:
    #         r = remote('socket.cryptohack.org', 13422, level = 'info')
    #         r.readline()

    #         print(f"\nexperience n°{index_test}")

    #         #flag = challenge_resolve(interface_, target)
    #         res = challenge_resolve(interface)

    #         # Print le flag
    #         print(res[0])
    #         nb_mistake.append(res)

    #         r.close()
    #         break
    #     except:
    #         print(f"\n======================================================================")
    #         print(f"======================= Abandon nique sa mère =========================")
    #         print(f"=======================================================================")
    #         nb_mistake.append(["fail"])
    #         r.close()

    # print(nb_mistake)

    

