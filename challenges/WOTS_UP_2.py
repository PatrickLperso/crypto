import hashlib
import json
from os import urandom
from Crypto.Cipher import AES

import os , sys

BYTE_MAX = 255
KEY_LEN = 32

def get_half_key(message1, message2, signature1, signature2_attack):
    # on suppose signature1, message1, message2, public_key access
    nb_hash_m1 = list(map(lambda x:255-x, list(hashlib.sha256(message1).digest())))
    nb_hash_m2 = list(map(lambda x:255-x, list(hashlib.sha256(message2).digest())))
    data_hash = hashlib.sha256(message2).digest()
    data_hash_bytes = bytearray(data_hash)

    for i in range(KEY_LEN):
        if nb_hash_m2[i] > nb_hash_m1[i]:
        
            sig_item = signature1[i]
            for k in range(nb_hash_m2[i]-nb_hash_m1[i]):
                sig_item = hashlib.sha256(sig_item).digest()

            if len(signature2_attack)<KEY_LEN:
                signature2_attack.append(sig_item)
            else:
                if signature2_attack[i]==None:
                    signature2_attack[i] = sig_item
                else:
                    assert signature2_attack[i] == sig_item
        else:
            if len(signature2_attack)<KEY_LEN:
                signature2_attack.append(None)
            else:
                continue


if __name__ == "__main__":
    path_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ressources/wots_up_2.json')

    with open(path_json) as f:
        data = json.load(f)
        transcripts = data["signatures"]
        iv = bytes.fromhex(data["iv"])
        enc = bytes.fromhex(data["enc"])
        public_key = list(map(lambda x:bytes.fromhex(x), data["public_key"]))
    
    message2 = f"{public_key[0].hex()} sent 999999 WOTScoins to me".encode()

    signature2_attack = []
    for index, transcript in enumerate(transcripts):
        signature1 = list(map(lambda x:bytes.fromhex(x), transcript["signature"]))
        message1 = transcript["message"].encode()

        # on recup les bytes sur la signature qu'on peut 
        get_half_key(message1, message2, signature1, signature2_attack)

        aes_key_attack = bytes([63 if s==None else s[0] for s in signature2_attack])
        print(f"aes_key_attack : {aes_key_attack}")
    
    
    cipher = AES.new(aes_key_attack, AES.MODE_CBC, iv)
    flag = cipher.decrypt(enc)
    print(f"flag : {flag}")
    assert flag == b'ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}'