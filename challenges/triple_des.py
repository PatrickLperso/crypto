from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests

IV = os.urandom(8)
FLAG = "crypto{toto}"


def xor(a, b):
    # xor 2 bytestrings, repeating the 2nd one if necessary
    return bytes(x ^ y for x,y in zip(a, b * (1 + len(a) // len(b))))

def encrypt(key, plaintext):
    try:
        key = bytes.fromhex(key)
        plaintext = bytes.fromhex(plaintext)
        plaintext = xor(plaintext, IV)

        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = xor(ciphertext, IV)

        return {"ciphertext": ciphertext.hex()}

    except ValueError as e:
        return {"error": str(e)}

def encrypt_flag(key):
    return encrypt(key, pad(FLAG.encode(), 8).hex())

def challenge(interface_encrypt, interface_encrypt_flag):
    # on utiliser le concept de weak key et semi key dans DES
    # https://en.wikipedia.org/wiki/Weak_key
    # Le XOR de l'IV disparaît en appliquant deux fois DES 

    # E_k1(E_k2(M)) = M
    weak_key_pair_1 = ("011F011F010E010E", "1F011F010E010E01") 
    weak_key_pair_2 = ("01E001E001F101F1", "E001E001F101F101") 

    # E_k(E_k(M)) = M
    weak_key = "FFFFFFFFFFFFFFFF"

    key_1 = weak_key_pair_1[0] + weak_key + weak_key_pair_2[0]
    key_2 = weak_key_pair_2[1] + weak_key +  weak_key_pair_1[1]

    # Test attaque weak keys
    plaintext = "bf9e1e581d51fcf1"
    cipher_1 = interface_encrypt(key_1, plaintext)["ciphertext"]
    cipher_2 = interface_encrypt(key_2, cipher_1)["ciphertext"]

    assert plaintext==cipher_2

    # Challenge
    cipher_flag = interface_encrypt_flag(key_1)["ciphertext"]
    flag_padded = interface_encrypt(key_2, cipher_flag)["ciphertext"]


    return unpad(bytes.fromhex(flag_padded),8).decode()

def encrypt_request(key, plaintext):
    return requests.get(f"https://aes.cryptohack.org/triple_des/encrypt/{key}/{plaintext}").json()

def encrypt_flag_request(key):
    return requests.get(f"https://aes.cryptohack.org/triple_des/encrypt_flag/{key}").json()


if __name__ == "__main__":

    # ================ Test offline ====================
    interface_encrypt = encrypt
    interface_encrypt_flag = encrypt_flag

    flag = challenge(interface_encrypt, interface_encrypt_flag)
    assert flag == FLAG


    # ================ Challenge ====================
    interface_encrypt = encrypt_request
    interface_encrypt_flag = encrypt_flag_request

    flag = challenge(interface_encrypt, interface_encrypt_flag)
    assert flag == "crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}"
