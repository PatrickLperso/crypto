from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
import os
from tqdm import tqdm 

import jwt

def get_pubkey_request():
    return requests.get(f"https://web.cryptohack.org/rsa-or-hmac/get_pubkey").json()

def create_session_request(username):
    return requests.get(f"https://web.cryptohack.org/rsa-or-hmac/create_session/{username}/").json()

def authorise_request(token):
    return requests.get(f"https://web.cryptohack.org/rsa-or-hmac/authorise/{token}/").json()


def challenge(interface_session, interface_authorise, interface_get_pubkey):
    username = "toto"
    pubkey = interface_get_pubkey()["pubkey"]

    # pour que le challenge focntionne il faut patcher une execption dans prepare_key qui verifie que la clé symétrique utilisé 
    # n'est pas une clé asymétrique. Pour voir le patch
    # cat /home/linuxperso/crypto/crypto_venv/lib/python3.11/site-packages/jwt/algorithms.py | grep -A10 "def prepare_key(self, key: str | bytes) -> bytes:"
    
    token = jwt.encode({'username': username, 'admin': True}, pubkey, algorithm='HS256')

    res = interface_authorise(token)["response"].split("flag: ")[1]

    return res

if __name__ == "__main__":
    interface_session = create_session_request
    interface_authorise = authorise_request
    interface_get_pubkey = get_pubkey_request

    flag = challenge(interface_session, interface_authorise, interface_get_pubkey)
    assert flag == "crypto{Doom_Principle_Strikes_Again}"




