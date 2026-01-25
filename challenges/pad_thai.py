from Crypto.Cipher import AES
import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
from pwn import *
from functools import reduce
from operator import xor
from tqdm import tqdm
import json 

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom


r = remote('socket.cryptohack.org', 13421, level = 'info')

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

class Challenge:
    def __init__(self):
        self.before_input = "Let's practice padding oracle attacks! Recover my message and I'll send you a flag.\n"
        self.message = urandom(16).hex()
        
        self.key = urandom(16)

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        #ct = cipher.encrypt(self.message)
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
        return {"result": good}

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


def challenge_resolve(interface):

    data_interface = bytes.fromhex(interface({"option" : "encrypt"})["ct"])
    iv = data_interface[:16]
    cipher_message = data_interface[16:]
    
    plaintext = b""

    for index_bloc in range(0,len(cipher_message), 16):
        # bloc par bloc (AES CBC) on va déchiffrer le message chiffré
        found = b""
        print(f"\n=====================================================")
        print(f"=======================bloc n°{index_bloc//16+1}=======================")
        print(f"=====================================================")
        for i in tqdm(range(1,17)):
            # byte par byte on va déchiffrer la sortie du bloc AES
            for k in range(256):
                # on bruteforce le byte jusqu'a trouver le bon padding
                byte_bruteforce = bytes([k]).hex() 

                # Création de l'IV (payload), on met des 0(bytes([0]*(16-i)).hex()) + octets à bruteforcer (bytes_test) + octets découverts (found.hex() )
                cipher = bytes([0]*(16-i)).hex() + byte_bruteforce + found.hex() 
                # Ajout du chiffré 
                cipher += cipher_message[index_bloc:index_bloc+16].hex()

                # on teste si le padding est valide ou non
                res = interface({"option" : "unpad", "ct":cipher})["result"]

                """
                si le padding est correct, on a trouvé le bon byte
                maintenant pour bruteforcer le byte suivant il faut qu'on s'assure que le(s) byte(s) précédemment trouvé(s)
                dont celui qui vient d'être trouvé feront un padding correct pour le prochain byte à trouver lors 
                du XOR avec les bytes du cipher post opération déchiffrement AES 
                ex : 

                On cherche le premier byte WW
                [000000000000000000000000000000                      + WW                             ]       XOR      AES(cipher)     =     ..............................01
                [000000000000000000000000000000                      + 2e                             ]       XOR      AES(cipher)     =     ..............................01
                WW = 2e (bruteforce)

                On calcule le nouveau byte de fin pour trouver XX
                [0000000000000000000000000000 XX                     + (2e XOR 01 XOR 02)             ]       XOR      AES(cipher)     =     ............................0202
                [0000000000000000000000000000 0d                     + (2e XOR 01 XOR 02)             ]       XOR      AES(cipher)     =     ............................0202
                XX = 0d

                On a trouvé XX on va calculer le nouveau bytes de fin 
                [00000000000000000000000000 YY + (0d XOR 02 XOR 03)  + (2e XOR 01 XOR 2 XOR 2 XOR 03) ]       XOR      AES(cipher)     =     ..........................030303
                on trouve YY etc.

                etc ... jusqu'à trouver AA
                [AA + ... + ... + ...          + (0d XOR ... XOR 15)  + (2e XOR 01 XOR ...... XOR 15) ]       XOR      AES(cipher)     =     10101010101010101010101010101010
                """

                if res:
                    if i!=16:
                        found = Xor(bytes.fromhex(bytes_test)+found, bytes([i] * i), bytes([i+1] * i))
                    else:
                        found = bytes.fromhex(bytes_test)+found
                    break
                else:
                    continue
        
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

    flag = interface({"option" : "check", "message":plaintext.decode()})["flag"]
    return flag


if __name__ == "__main__":
    """
    un peu de doc
    - https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/
    - https://www.brunorochamoura.com/posts/cbc-padding-oracle/
    """

    # ================ Home test ==================
    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = challenge_resolve(interface_)
    assert flag == FLAG

    # ================ Cryptohack (asssez rapide) ==================
    interface_ = interface

    print(r.readline())
    flag = challenge_resolve(interface_)
    assert flag == "crypto{if_you_ask_enough_times_you_usually_get_what_you_want}"

 