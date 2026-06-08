from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os,sys

# Ajout du répertoire eliptic curve
#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from crypto_core.polhig_hellman import polhig_hellman
from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass

def encrypt_flag(shared_secret: int, message):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    
    # Encrypt flag
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, 16))

    print(f"key:{key}")
    print(f"iv:{iv}")
    print(f"ciphertext:{ciphertext}")
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data


def decrypt_flag(shared_secret, iv_hex, encrypted_flag_hex):

    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    iv = bytes.fromhex(iv_hex)
    encrypted_flag = bytes.fromhex(encrypted_flag_hex)

    print(f"key:{key}")
    print(f"iv:{iv}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(encrypted_flag)
    print(f"plaintext_padded:{plaintext_padded}")

    # Supprimer le padding PKCS#7
    plaintext = unpad(plaintext_padded, 16)
    return plaintext

if __name__ == "__main__":
    # Note : A MOV attack is also possible 
    # To read https://risencrypto.github.io/WeilMOV/

    curve3=WeierStrass(-35, 98, 1331169830894825846283645180581)
    G=PointWeirstrass(curve3, 479691812266187139164535778017,568535594075310466177352868412)

    bob_public_key=PointWeirstrass(curve3, 1290982289093010194550717223760,762857612860564354370535420319)
    alice_public_key=PointWeirstrass(curve3, 1110072782478160369250829345256,800079550745409318906383650948)
    
    order_G = 103686954799254136375814
    order_prime_decomposition_G = [(2,1), (7,1), (271,1),(23687,1), (1153763334005213,1)] 

    alice_private_key,modulo=polhig_hellman(G, alice_public_key, order_G, order_prime_decomposition_G, fast=True)
    assert alice_private_key == 29618469991922269
    assert alice_private_key*G == alice_public_key

    shared_secret_point=alice_private_key*bob_public_key
    shared_secret_key = shared_secret_point.x

    iv_hex='eac58c26203c04f68d63dc2c58d79aca'
    encrypted_flag_hex='bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'
    flag = decrypt_flag(shared_secret_key, iv_hex, encrypted_flag_hex)
    
    assert flag==b'crypto{MOV_attack_on_non_supersingular_curves}'