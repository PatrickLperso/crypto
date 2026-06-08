from sage.all import Integer
from Crypto.Util.number import bytes_to_long, long_to_bytes
import os, sys

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from crypto_core.Rsa import Rsa_privatekey, Rsa_publickey


# from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

# e = 0x10001

# # n will be 8 * (100 + 100) = 1600 bits strong (I think?) which is pretty good
# p = getPrime(100)
# q = getPrime(100)
# phi = (p - 1) * (q - 1)
# d = inverse(e, phi)

# n = p * q

# FLAG = b"crypto{???????????????}"
# pt = bytes_to_long(FLAG)
# ct = pow(pt, e, n)

# print(f"n = {n}")
# print(f"e = {e}")
# print(f"ct = {ct}")

# pt = pow(ct, d, n)
# decrypted = long_to_bytes(pt)
# assert decrypted == FLAG



if __name__ == "__main__":
    # Très conretement, on est dans le quadractic sieve
    # le produits des nombres premiers est trop petit et donc cassable
    # a implémenter l'attaque par moi-même plutot que passer par sage

    p,q = Integer(984994081290620368062168960884976209711107645166770780785733).factor()
    print(p,q)


    p = int(p[0])
    q = int(q[0])

    n = 984994081290620368062168960884976209711107645166770780785733
    e = 65537
    ct = 948553474947320504624302879933619818331484350431616834086273
    ct_hex  = long_to_bytes(ct).hex()


    rsa_private = Rsa_privatekey(p, q, e=65537)
    assert b'crypto{N33d_b1g_pR1m35}' == rsa_private.decrypt(ct_hex, bytes_output= True)