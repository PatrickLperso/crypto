import hashlib
import json
from os import urandom
from Crypto.Cipher import AES
import os , sys

BYTE_MAX = 255
KEY_LEN = 32


class Winternitz:
    def __init__(self, priv_seed=urandom(KEY_LEN), priv_key=None):
        if priv_key==None:
            self.priv_key = []
            for _ in range(KEY_LEN):
                priv_seed = self.hash(priv_seed)
                self.priv_key.append(priv_seed)
        else:
            priv_seed = priv_key
            self.priv_key = [priv_key]
            for _ in range(KEY_LEN-1):
                priv_seed = self.hash(priv_seed)
                self.priv_key.append(priv_seed)

        self.gen_pubkey()

    def gen_pubkey(self):
        self.pub_key = []
        for i in range(KEY_LEN):
            pub_item = self.hash(self.priv_key[i])
            for _ in range(BYTE_MAX):
                pub_item = self.hash(pub_item)
            self.pub_key.append(pub_item)

    def hash(self, data):
        return hashlib.sha256(data).digest()

    def sign(self, data):
        data_hash = self.hash(data)
        data_hash_bytes = bytearray(data_hash)
        sig = []
        for i in range(KEY_LEN):
            sig_item = self.priv_key[i]
            int_val = data_hash_bytes[i]
            hash_iters = BYTE_MAX - int_val
            for _ in range(hash_iters):
                sig_item = self.hash(sig_item)
            sig.append(sig_item)
        return sig

    def verify(self, signature, data):
        data_hash = self.hash(data)
        data_hash_bytes = bytearray(data_hash)
        verify = []
        for i in range(KEY_LEN):
            verify_item = signature[i]
            hash_iters = data_hash_bytes[i] + 1
            for _ in range(hash_iters):
                verify_item = self.hash(verify_item)
            verify.append(verify_item)
        return self.pub_key == verify

def get_half_key(message1, message2, signature1):
    # on suppose signature1, message1, message2, public_key access
    signature2_attack=[]
    nb_hash_m1 = list(map(lambda x:255-x, list(hashlib.sha256(message1).digest())))
    nb_hash_m2 = list(map(lambda x:255-x, list(hashlib.sha256(message2).digest())))
    data_hash = hashlib.sha256(message2).digest()
    data_hash_bytes = bytearray(data_hash)

    for i in range(KEY_LEN):
        if nb_hash_m2[i] > nb_hash_m1[i]:
        
            sig_item = signature1[i]
            for k in range(nb_hash_m2[i]-nb_hash_m1[i]):
                sig_item = hashlib.sha256(sig_item).digest()
        
            signature2_attack.append(sig_item)
        else:
            signature2_attack.append(b"?")
    
    aes_key_attack = bytes([s[0] for s in signature2_attack])

    return aes_key_attack

def challenge(message1, message2, signature1):
    # ============= c'est un hasard + une vulnérabilité ===============
    # La clé privée est mal générée:
    # priv_key = [hash(priv_seed),hash(hash(priv_seed)), ..., ..., ..., ..., ..., ..., ...]
    """
    def __init__(self, priv_seed=urandom(KEY_LEN)):
        self.priv_key = []
        for _ in range(KEY_LEN):
            priv_seed = self.hash(priv_seed)
            self.priv_key.append(priv_seed)
        self.gen_pubkey()
    """

    # Enfin la génration de la signature à partir de la clé privée est légerment différente à d'habitude:
    """
    for i in range(KEY_LEN):
        sig_item = self.priv_key[i]
        int_val = data_hash_bytes[i]

        # pas standard, normalement hash_iters = int_val = data_hash_bytes[i]
        hash_iters = BYTE_MAX - int_val
        for _ in range(hash_iters):
            sig_item = self.hash(sig_item)
        sig.append(sig_item)
    return sig
    """
    # Ainsi, si on calcule le nombre de hash réalisés sur la clé privée avec le message "WOTS Up???, on tombe sur :
    # list(map(lambda x:255-x, list(w.hash(b"WOTS Up???")))) = [0, 197, 31, 179, 248, ...]
    # On remarque un 0 pour le premier élément 
    # Donc signature1[0] = priv_key[0]
    # Et donc on peut reconsituer mla clé privée car
    # priv_key = [hash(priv_seed),hash(hash(priv_seed)), ..., ..., ..., ..., ..., ..., ...]
 
    priv_key = signature1[0]
    w_new = Winternitz(priv_key=priv_key)

    assert signature1 == w_new.sign(message1)

    signature2 = w_new.sign(message2)
    aes_key = bytes([s[0] for s in signature2])
    return aes_key

    

path_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ressources/wots_up.json')

if __name__ == "__main__":
    
    #===========================================
    # ========== Challenge local ===============
    #===========================================
    w = Winternitz()

    message1 = b"WOTS Up???"
    signature1 = w.sign(message1)

    message2 = b"Sign for flag"
    signature2 = w.sign(message2)
    aes_key = bytes([s[0] for s in signature2])

    # ================ useless mais permet de récupérer 50% de la clé privée ===========
    aes_key_attack_v1 = get_half_key(message1, message2, signature1)
    print(aes_key_attack_v1)

    # =================== Attack challenge =====================
    aes_key_attack_v2 = challenge(message1, message2, signature1)
    print(aes_key_attack_v2)

    assert aes_key == aes_key_attack_v2
    del w, message1, signature1, message2, signature2, aes_key, aes_key_attack_v1, aes_key_attack_v2

    #=========================================
    #=============== Cryptohack ==============
    #=========================================
    message1 = b"WOTS Up???"
    message2 = b"Sign for flag"

    w = Winternitz()

    with open(path_json) as f:
        d = json.load(f)
        signature1 = list(map(lambda x:bytes.fromhex(x), d["signature"]))
        iv = bytes.fromhex(d["iv"])
        enc = bytes.fromhex(d["enc"])

    aes_key_attack_v1 = get_half_key(message1, message2, signature1)
    aes_key_attack_flag = challenge(message1, message2, signature1)

    print(aes_key_attack_v1)
    print(aes_key_attack_flag)

    cipher = AES.new(aes_key_attack_flag, AES.MODE_CBC, iv)
    flag = cipher.decrypt(enc)
    assert flag == b'ECSC{h4sh1ng_ch41n_r34ct1on_ff_}'


    



