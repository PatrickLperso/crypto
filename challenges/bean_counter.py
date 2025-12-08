import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import json
import string
import requests
from Crypto.Util.number import bytes_to_long, long_to_bytes
from tqdm import tqdm
from Crypto.Cipher import AES

KEY = os.urandom(32)

def encrypt_request():
    return requests.get("https://aes.cryptohack.org/bean_counter/encrypt/").json()

def challenge():
    cipher = bytes.fromhex(encrypt_request()["encrypted"])
    message_known = bytes.fromhex('89504E470D0A1A0A0000000D49484452')
    
    bytes_aes_nonce = long_to_bytes(bytes_to_long(message_known) ^ bytes_to_long(cipher[:16]))
    
    res = b""
    for index, byte_png in enumerate(cipher):
        res+=(byte_png^bytes_aes_nonce[index%len(bytes_aes_nonce)]).to_bytes(1, byteorder='little')

    return res

if __name__ == "__main__":
    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    csv_path = os.path.join(folder, f"bean_counter.png")

    # =========== challenge local ===========
    png_content = challenge()

    with open(csv_path, "wb") as f:
        f.write(png_content)

