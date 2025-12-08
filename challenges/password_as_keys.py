from Crypto.Cipher import AES
import hashlib
import random
import json
import string
import requests
from tqdm import tqdm
import os

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(message)

    return encrypted.hex()

def decrypt(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return decrypted

def bruteforce(cipher):
    # /usr/share/dict/words from
    # https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words

    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")

    with open(os.path.join(folder, "words")) as f:
        words = [w.strip() for w in f.readlines()]

    for word in tqdm(words):
        if word == "sentimentalizing":
            pass
        key = hashlib.md5(word.encode()).digest()
        decrypted = decrypt(cipher, key)
        try:
            if decrypted.decode().startswith("crypto"):
                break
        except:
            pass
    return word, decrypted

if __name__ == "__main__":
    BASE_URL = 'https://web.cryptohack.org/'

    response = requests.get(f'{BASE_URL}/passwords_as_keys/encrypt_flag/').json()
    cipher = response["ciphertext"]

    word, flag = bruteforce(cipher)
    assert word=="bluebell"
    assert flag == b'crypto{k3y5__r__n07__p455w0rdz?}'

    # message = b"crypto{blablabl}"
    # word = "sentimentalizing"
    # key = hashlib.md5(word.encode()).digest()
    # cipher = encrypt(message, key)

    # assert message == decrypt(cipher, key)

    # word_found, message_found = bruteforce(cipher)
    # assert word==word_found and message==message_found
