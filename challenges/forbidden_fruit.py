from Crypto.Cipher import AES
import os, sys
import requests

# Ajout du répertoire repeated nonce
#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from crypto_core.repeated_nonce_gcm import challenge


def decrypt_request(nonce, ciphertext, tag, associated_data):
    return requests.get(f"https://aes.cryptohack.org/forbidden_fruit/decrypt/{nonce}/{ciphertext}/{tag}/{associated_data}").json()

def encrypt_request(plaintext):
    return requests.get(f"https://aes.cryptohack.org/forbidden_fruit/encrypt/{plaintext}/").json()


if __name__ == "__main__":

    for k in range(10):
        mod = 0x100000000000000000000000000000087
        interface_encrypt = encrypt_request
        interface_decrypt = decrypt_request

        flag = challenge(interface_encrypt, interface_decrypt, mod)
        print(flag)
        assert flag == b"crypto{https://github.com/attr-encrypted/encryptor/pull/22}"