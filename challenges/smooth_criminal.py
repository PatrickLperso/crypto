from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os
import sys

# Ajout du répertoire eliptic curve
#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from crypto_core.Polhig_Hellman import polhig_hellman
from crypto_core.Eliptic_curve import WeierStrass, PointWeirstrass

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
    Point = namedtuple("Point", "x y")

    #  ======== Test encrypt and decrypt AES using shared point ========
    shared_secret_point = Point(x=280810182131414898730378982766101210916, y=291506490768054478159835604632710368904)

    Point = namedtuple("Point", "x y")
    message=b"ceci est un test"
    cipher=encrypt_flag(shared_secret_point.x, message)
    assert decrypt_flag(shared_secret_point.x, cipher["iv"], cipher['encrypted_flag'])==message

    #  =================== Smooth Criminal Challenge ====================

    curve2=WeierStrass(2, 3, 310717010502520989590157367261876774703)
    G=PointWeirstrass(curve2, 179210853392303317793440285562762725654,105268671499942631758568591033409611165)

    bob_public_key=PointWeirstrass(curve2, 272640099140026426377756188075937988094,51062462309521034358726608268084433317)
    alice_public_key=PointWeirstrass(curve2, 280810182131414898730378982766101210916,291506490768054478159835604632710368904)

    order=310717010502520989590206149059164677804
    order_prime_decomposition=[(2,2),(3,7),(139,1),(165229,1),(31850531,1),(270778799,1),(179317983307,1)]

    bob_private_key,modulo=polhig_hellman(G, bob_public_key, order, order_prime_decomposition, fast=True)

    assert bob_private_key*G == bob_public_key
    assert bob_private_key == 23364484702955482300431942169743298535

    shared_secret_point=bob_private_key*alice_public_key
    shared_secret_key = shared_secret_point.x

    iv_hex='07e2628b590095a5e332d397b8a59aa7'
    encrypted_flag_hex='8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'
    flag = decrypt_flag(shared_secret_key, iv_hex, encrypted_flag_hex)
    assert flag == b'crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}'