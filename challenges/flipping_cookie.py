
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
import requests
from time import time, sleep
from Crypto.Util.number import bytes_to_long, long_to_bytes

KEY =  os.urandom(32)
FLAG = "crypto{??????????}"

def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}

def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()
    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()
    return {"cookie": ciphertext}

def get_cookie_request():
    return requests.get("https://aes.cryptohack.org/flipping_cookie/get_cookie/").json()

def check_admin_request(cookie, iv):
    return requests.get(f"https://aes.cryptohack.org/flipping_cookie/check_admin/{cookie}/{iv}").json()

def challenge(interface_get_cookie, interface_check_admin, original_text, new_text):
    
    t1 = time()
    expires_t1 = (datetime.today() + timedelta(days=1))
    ciphertext = bytes.fromhex(interface_get_cookie()["cookie"])
    t2=time()
    
    iv = ciphertext[:16]
    cookie = ciphertext[16:]
    iv_ = long_to_bytes(bytes_to_long(new_text) ^ bytes_to_long(original_text) ^ bytes_to_long(iv)) 

    flag = interface_check_admin(cookie.hex(), iv_.hex())["flag"]
    return flag



if __name__ == "__main__":
    iv = os.urandom(16)
    # =============== Attention ici on joue uniquement sur le premier bloc =============
    
    # ========= local test =======
    interface_get_cookie = get_cookie
    interface_check_admin = check_admin

    original_text = b'admin=False;expi'
    new_text = b'admin=True;;expi'

    res = challenge(interface_get_cookie, interface_check_admin, original_text, new_text)
    assert res == FLAG

    # ========= online =======

    interface_get_cookie = get_cookie_request
    interface_check_admin = check_admin_request

    original_text = b'admin=False;expi'
    new_text = b'admin=True;;expi'

    res = challenge(interface_get_cookie, interface_check_admin, original_text, new_text)
    assert res == b"crypto{4u7h3n71c4710n_15_3553n714l}"
