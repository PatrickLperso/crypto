from Crypto.Cipher import AES
import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests


KEY =  os.urandom(32)
FLAG = "crypto{????????????????????????}"


def encrypt(plaintext, iv):
    plaintext = bytes.fromhex(plaintext)
    iv = bytes.fromhex(iv)
    if len(iv) != 16:
        return {"error": "IV length must be 16"}

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext)
    ciphertext = encrypted.hex()

    return {"ciphertext": ciphertext}

def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

def encrypt_request(plaintext,iv):
    return requests.get(f"https://aes.cryptohack.org/symmetry/encrypt/{plaintext}/{iv}").json()

def encrypt_flag_request():
    return requests.get(f"https://aes.cryptohack.org/symmetry/encrypt_flag/").json()

def challenge(interface_encrypt, interface_encrypt_flag):
    cipher_text = bytes.fromhex(interface_encrypt_flag()["ciphertext"])
    iv = cipher_text[:16]
    cipher_message = cipher_text[16:]

    message_known = b"0"*len(cipher_message)
    cipher_known = bytes.fromhex(interface_encrypt(message_known.hex(), iv.hex())["ciphertext"])

    solution = b""
    for k in range(len(cipher_message)//16):
        solution +=long_to_bytes(bytes_to_long(cipher_message[k*16:(k+1)*16]) ^ bytes_to_long(message_known[k*16:(k+1)*16]) ^ bytes_to_long(cipher_known[k*16:(k+1)*16]))
    return solution

if __name__ == "__main__":

    # ========= local test =======
    interface_encrypt = encrypt
    interface_encrypt_flag = encrypt_flag

    res = challenge(interface_encrypt, interface_encrypt_flag)
    assert res == FLAG.encode()

    # ========= local test =======
    interface_encrypt = encrypt_request
    interface_encrypt_flag = encrypt_flag_request

    res = challenge(interface_encrypt, interface_encrypt_flag)
    assert res == b'crypto{0fb_15_5ymm37r1c4l_!!!11!'