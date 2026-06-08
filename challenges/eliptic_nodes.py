import os, sys

from collections import namedtuple
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes

from sage.all import EllipticCurve, GF


#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from crypto_core.polhig_hellman import polhig_hellman
from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from crypto_core.modular_arithmetic import ChineseRemainder, pgcd

FLAG = b"crypto{???????????????????????}"

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# The point at infinity (origin for the group law).
O = 'Origin'


def check_point(P):
    # this looks good 
    if P == O:
        return True
    else: 
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P):
    # this looks good 
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P, Q):
    # this looks good

    # ouep si point à l'infini 
    if P == O:
        return Q
    elif Q == O:
        return P
    
    # ouep si inverse, on renvoie le point à l'infini
    elif Q == point_inverse(P):
        return O
    
    # addition & doubling cohérent
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P, n):
    # this looks good also nothing missed
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


def public_key():
    d = bytes_to_long(FLAG)
    return double_and_add(G, d)


# Define the curve
# p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

# gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
# gy = 225987949353410341392975247044711665782695329311463646299187580326445253608
# G = Point(gx, gy)
# Q = public_key()

# print(Q)
# Point(x=2582928974243465355371953056699793745022552378548418288211138499777818633265, y=2421683573446497972507172385881793260176370025964652384676141384239699096612)

if __name__ == "__main__":

    p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

    Gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
    Gy = 225987949353410341392975247044711665782695329311463646299187580326445253608
    Qx = 2582928974243465355371953056699793745022552378548418288211138499777818633265
    Qy = 2421683573446497972507172385881793260176370025964652384676141384239699096612

    # Système 2 équations, 2 inconnus pour retrouver les coefficients de la courbe 
    a1 = -Gx
    b1 = -1
    c1 = (-Gy**2+Gx**3)%p

    a2 = -Qx
    b2 = -1
    c2 = (-Qy**2+Qx**3)%p   

    delta = (a1*b2-a2*b1)%p
    assert delta !=0

    # Résolution système Ax=B mod p matriciel pour trouver a et b
    a = ((c1*b2-c2*b1)*pow(delta, -1, p))%p
    b = ((c1-a1*a)*pow(b1,-1,p))%p

    # On se rend compt que la courbe est singulière
    curve = WeierStrass(a, b, p, secure=False)
    assert curve.isSingular()

    G = PointWeirstrass(curve, Gx, Gy)
    Q = PointWeirstrass(curve, Qx, Qy)

    #on doit savoir si on est usp ou autre 
    x = GF(p)["x"].gen()
    f = x ** 3 + a*x + b
    roots = f.roots()
    print(roots)

    # la je commence à buguer 
    # https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/singular_curve.py

    if len(roots)==1:
        print("this is the cusp case")
    else:
        # c'est notre cas
        print("This is the node case")
        
        # on recherche la racine double 
        if roots[0][1] == 2:
            alpha, beta = roots[0][0], roots[1][0]
        elif roots[1][1] == 2:
            beta, alpha = roots[0][0], roots[1][0]

        # alors https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp/61434#61434

        # Mapping du problème de l'ECDLP vers le DLP
        # à lire les solutions en details pour bien comprednre le transfert de ECDLP vers DLP
        t = (alpha - beta).sqrt()
        u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha))
        v = (Qy + t * (Qx - alpha)) / (Qy - t * (Qx - alpha))
        
        # on resout le problème du log discrete avec sagemath pour utiliser le index calculus 
        # qui est super performant pour le DLP
        secret_key = int(v.log(u))
    
    assert long_to_bytes(secret_key) == b'crypto{s1ngul4r_s1mplif1c4t1on}'
