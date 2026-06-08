from Crypto.Util.number import getPrime
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
import hashlib
import sys, os
from sage.all import EllipticCurve, GF
from functools import reduce

from deriving_symetric_keys import decrypt_flag 

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from crypto_core.polhig_hellman import polhig_hellman
from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from crypto_core.modular_arithmetic import ChineseRemainder, pgcd

FLAG = b"crypto{???????????????????}"


def gen_key_pair(G, nbits):
    n = random.getrandbits(nbits)
    P = n*G
    return P.xy()[0], n


def gen_shared_secret(P, n):
	S = n*P
	return S.xy()[0]


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

"""
# Efficient key exchange
nbits = 64
pbits = 256

# Curve parameters
p = getPrime(pbits)
a = 1
b = 4
E = EllipticCurve(GF(p), [a,b])
G = E.gens()[0]

print(f"Sending curve parameters:")
print(f"{E}")
print(f"Generator point: {G}\n")

# Generate key pairs
ax, n_a = gen_key_pair(G, nbits)
bx, n_b = gen_key_pair(G, nbits)

print(f"Alice sends public key: {ax}")
print(f"Bob sends public key: {bx}\n")

# Calculate point from Bob
B = E.lift_x(bx)

# Encrypted flag with shared secret
shared_secret = gen_shared_secret(B,n_a)
encrypted_flag = encrypt_flag(shared_secret)

print(f"Alice sends encrypted_flag: {encrypted_flag}")
"""

if __name__ == "__main__":

    # =========== Curve parameter ===============
    a = 1
    b = 4
    p = 99061670249353652702595159229088680425828208953931838069069584252923270946291

    # note that G order is the curve order because it's a generator
    Gx, Gy = 43190960452218023575787899214023014938926631792651638044680168600989609069200 , 20971936269255296908588589778128791635639992476076894152303569022736123671173 

    # =========== Challenge parameter ===============

    threshold_pollard = 100000**2
    info_to_recover =2**64

    alice_x = 87360200456784002948566700858113190957688355783112995047798140117594305287669
    bob_x = 6082896373499126624029343293750138460137531774473450341235217699497602895121
    iv = 'ceb34a8c174d77136455971f08641cc5'
    encrypted_flag = 'b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453'
    
    curve = WeierStrass(a, b, p)
    # ======== g is a generator ===========
    G = PointWeirstrass(curve, Gx, Gy)

    A = curve.point_from_x(alice_x)
    B = curve.point_from_x(bob_x)

    # =========== Curve parameters and subgroup to exclude because hardly breakable ==============
    E = EllipticCurve(GF(p), [a, b])
    order = E.order()
    order_prime_decomposition = [(int(k[0]), int(k[1])) for k in list(order.factor())]
    list_prime_avoid = [ k[0] for k in order_prime_decomposition if k[0]>threshold_pollard]
    assert reduce(lambda x, y: x * y, [ k[0]**k[1] for k in order_prime_decomposition if k[0] not in list_prime_avoid]) > info_to_recover

    # =========== Test =============
    nbits = 64
    c = random.getrandbits(nbits)
    C = c*G

    crt_system_equations = polhig_hellman(G, C, order, order_prime_decomposition, fast=True,list_prime_avoid=list_prime_avoid)
    res = ChineseRemainder(crt_system_equations, True)

    assert C == res[0]*G

    # ===== Recovering the shared secret & Flag =====

    crt_system_equations = polhig_hellman(G, B, order, order_prime_decomposition, fast=True,list_prime_avoid=list_prime_avoid)
    res = ChineseRemainder(crt_system_equations, True)

    if B != (res[0]*G): 
        # on test si le point généré par P = n*G == E.lift_x(P.xy()[0])
        # si ce n'est pas le cas, le point obtenu n'est pas le bon (autrement dit P = n*G == - E.lift_x(P.xy()[0]))
        # et on est censé casser -B pour en déduire la clé secrete de B

        crt_system_equations = polhig_hellman(G, -B, order, order_prime_decomposition, fast=True,list_prime_avoid=list_prime_avoid)
        res = ChineseRemainder(crt_system_equations, True)
        b_secret = -res[0]%order
    else:
        b_secret = res[0]
    
    assert B == (b_secret*G)

    shared_secret = b_secret*A
    flag = decrypt_flag(shared_secret.x, iv, encrypted_flag)
    print(flag)
    assert flag == 'crypto{d0nt_l3t_n_b3_t00_sm4ll}'




