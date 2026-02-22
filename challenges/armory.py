#!/usr/bin/env python3

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes


FLAG = b"crypto{???????????????????????}"
PRIME = 77793805322526801978326005188088213205424384389488111175220421173086192558047


def _eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def make_deterministic_shares(minimum, shares, secret, prime):
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")

    coefs = [secret]
    for i in range(1, shares + 1):
        coef = hashlib.sha256(coefs[i-1]).digest()
        coefs.append(coef)
    coefs = [int.from_bytes(p, 'big') for p in coefs]
    poly = coefs[:minimum]

    points = []
    for i in range(1, shares + 1):
        point = _eval_at(poly, coefs[i], prime)
        points.append((coefs[i], point))

    return points


# shares = make_deterministic_shares(minimum=3, shares=7, secret=FLAG, prime=PRIME)
# for share in shares:
#     print(share)

if __name__ == "__main__":
    x1 = 105622578433921694608307153620094961853014843078655463551374559727541051964080
    y1 = 25953768581962402292961757951905849014581503184926092726593265745485300657424

    # on génère les coefficents du polynome de manière récursive [a0, a1, a2] = [a0, sha256(a0), sha256(a1)]
    """
    coef = hashlib.sha256(coefs[i-1]).digest()
    """
    # Et on utilise ces coefficients pour les évalutions polynomiales
    # Donc a1 = x1, a2=x2 etc.
    """
    point = _eval_at(poly, coefs[i], prime)
    points.append((coefs[i], point))
    """
    a1 = x1
    a2 = bytes_to_long(hashlib.sha256(long_to_bytes(a1)).digest())

    # y1 = x1**2a2+x1*a1+a0 % p <=> a0 = y1 - (x1**2a2+x1*a1) % p 
    a0 = (y1 - pow(x1,2, PRIME)*a2-x1*a1)%PRIME
    assert long_to_bytes(a0) == b'crypto{fr46m3n73d_b4ckup_vuln?}'w
