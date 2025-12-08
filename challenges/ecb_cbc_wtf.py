from Crypto.Cipher import AES
import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests

KEY =  os.urandom(32)
FLAG = "crypto{????????????????????????}"

def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}

def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}


def challenge(interface_encrypt, interface_decrypt):
    cipher = bytes.fromhex(interface_encrypt()["ciphertext"])
    iv = cipher[:16]
    cipher_message = cipher[16:]
    
    uncipher_message_prexor = bytes.fromhex(interface_decrypt(cipher_message.hex())["plaintext"])

    res = b""

    for k in range(len(cipher_message)//16):
        if k == 0:
            res += long_to_bytes(bytes_to_long(iv) ^ bytes_to_long(uncipher_message_prexor[0:16]) )
        else:
            res += long_to_bytes(bytes_to_long(cipher_message[16*(k-1):16*(k)]) ^ bytes_to_long(uncipher_message_prexor[16*k:16*(k+1)]) )
    return res

def encrypt_flag_request():
    return requests.get("https://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/").json()

def decrypt_flag_request(ciphertext):
    return requests.get(f"https://aes.cryptohack.org/ecbcbcwtf/decrypt/{ciphertext}").json()

if __name__ == "__main__":

    # ========= local test =======
    interface_encrypt = encrypt_flag
    interface_decrypt = decrypt

    res = challenge(interface_encrypt, interface_decrypt)
    assert res == FLAG.encode()

    # ========= online =======

    interface_encrypt = encrypt_flag_request
    interface_decrypt = decrypt_flag_request

    res = challenge(interface_encrypt, interface_decrypt)
    assert res == b'crypto{3cb_5uck5_4v01d_17_!!!!!}'