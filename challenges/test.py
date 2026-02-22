from sage.all import GF, Integer, PolynomialRing
import sys, os
from Crypto.Util.number import bytes_to_long, long_to_bytes

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from galois_field import GF2_k

F2 = GF(2)

# Polynôme irréductible de GCM : x^128 + x^7 + x^2 + x + 1
R = PolynomialRing(F2, 'x')
x = R.gen()
mod_poly = x**128 + x**7 + x**2 + x + 1

# Corps GF(2^128) avec ce polynôme
F = GF(2**128, modulus=mod_poly, name='x')

def to_gcm_poly(value):
    # Convert to bytes (little-endian)
    value_bytes = value.to_bytes(16, 'little')
    
    # Reverse bits within each byte
    reflected_bytes = bytes(int(format(b, '08b')[::-1], 2) for b in value_bytes)
    
    # Convert back to integer
    reflected_value = int.from_bytes(reflected_bytes, 'big')
    
    return reflected_value

A = 0x0388DACE60B6A392F328C2B971B2FE78
B = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
C = 0x5E2EC746917062882C85B0685353DEB7

a = F.from_integer(to_gcm_poly(A))
b = F.from_integer(to_gcm_poly(B))
c = F.from_integer(to_gcm_poly(C))

assert a * b == c

# =========== Multiplication custom made library ==============
mod = 0x100000000000000000000000000000087
assert 2**128 + 2**7 + 2**2 + 2 + 1 == mod

a_ = GF2_k(to_gcm_poly(A),mod)
b_ = GF2_k(to_gcm_poly(B),mod)
c_ = GF2_k(to_gcm_poly(C),mod)

assert a_ * b_ == c_
assert hex(C) == hex(to_gcm_poly((a_ * b_).x))