from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
import os
from tqdm import tqdm 

import jwt

SECRET_KEY = "secret" # TODO: PyJWT readme key, change later
# voir le readme https://github.com/jpadilla/pyjwt

def authorise_request(token):
    return requests.get(f"https://web.cryptohack.org/jwt-secrets/authorise/{token}/").json()

def create_session_request(username):
    return requests.get(f"https://web.cryptohack.org/jwt-secrets/create_session/{username}/").json()


def challenge(interface_session, interface_authorise):
    username = "toto"
    token = jwt.encode({'username': username, 'admin': True}, SECRET_KEY, algorithm='HS256')

    res = interface_authorise(token)["response"].split("flag: ")[1]
    return res

if __name__ == "__main__":
    interface_session = create_session_request
    interface_authorise = authorise_request

    flag = challenge(interface_session, interface_authorise)
    assert flag == "crypto{jwt_secret_keys_must_be_protected}"




