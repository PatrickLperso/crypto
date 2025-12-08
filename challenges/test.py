from sage.all import EllipticCurve, GF, kronecker
import random as rd 
import sys, os
from twisted_mind_est import scalarmult
from Polhig_Hellman import polhig_hellman

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from Eliptic_curve import WeierStrass, PointWeirstrass
from Polhig_Hellman import polhig_hellman
from Modular_arithmetic import ChineseRemainder, pgcd

point_on_twist = lambda x,y,c,a,b,p : (x**3+a*x+b-c*y**2)%p==0

def weirstrass_to_twist(x1,y1,c,a,b,p):
    x = (x1*pow(c,-1,p))%p
    y = (y1*pow(c,-1,p)**2)%p
    assert point_on_twist(x,y,c,a,b,p)
    
    return x, y

def twist_to_weirstrass(x,y,c,a,b,p):
    return (x*c)%p, (y*c**2)%p

# ========== Pohlig Helman on breakable prime power order of Weirstrass curve ==========
def break_curve(a,b,p,scalar):

    E  = EllipticCurve(GF(p), [a, b])
    G = E.gens()
    curve_weirstrass = WeierStrass(a, b, p)
    G_weirstrass = PointWeirstrass(curve_weirstrass, int(tuple(G[0])[0]), int(tuple(G[0])[1]))

    order = E.order()
    prime_decomposition = order.factor()
    prime_decomposition =  [(int(k[0]),int(k[1])) for k in list(prime_decomposition)]
    list_prime_avoid = list(map(lambda x:x[0],list(filter(lambda x:x[0]>10**13,prime_decomposition))))

    print(f"EllipticCurve(K, [a, b]) order :{prime_decomposition}")

    x_scalar_weirstrass = int(scalarmult(scalar, G_weirstrass.x))
    Q = curve_weirstrass.point_from_x((x_scalar_weirstrass)%p) 
    crt_system_equations=polhig_hellman(G_weirstrass, Q, int(order), prime_decomposition, fast=True, list_prime_avoid=list_prime_avoid)

    return crt_system_equations
# ========== Pohlig Helman on breakable prime power order of the twist Weirstrass curve ==========

def break_twist(a,b,p,scalar):
    
    
    for c in range(-1, 50):
        if kronecker(c,p)==-1:
            Et = EllipticCurve(GF(p), [c**2*a, c**3*b])
            order_twist = Et.order()
            print(f"order_twist:{order_twist},c:{c}" )


            prime_decomposition = order_twist.factor()
            prime_decomposition =  [(int(k[0]),int(k[1])) for k in list(prime_decomposition)]
            list_prime_avoid = list(map(lambda x:x[0],list(filter(lambda x:x[0]>10**13,prime_decomposition))))

            print(f"EllipticCurve(GF(p), [c**2*a, c**3*b]) order (c:{c} non square over Fp) :{prime_decomposition}")

            G = Et.gens()
            curve_weirstrass_twist = WeierStrass(c**2*a, c**3*b,p)
            G_twist_weirstrass = PointWeirstrass(curve_weirstrass_twist, int(tuple(G[0])[0]), int(tuple(G[0])[1]))

            x,y = weirstrass_to_twist(G_twist_weirstrass.x, G_twist_weirstrass.y, c, a, b, p)
            # assert (G_twist_weirstrass.x, G_twist_weirstrass.y) == twist_to_weirstrass(x, y, c, a, b, p)
            # print("toto")

            
            x_scalar_twist = int(scalarmult(scalar, x))
            # on s'assure que le point est bien sur le twist (forme c*y**2)
            # assert kronecker(((x_scalar_twist**3+a*x_scalar_twist+b)*pow(c,-1,p)),p)==1

            # si on prend le point G sur la forme de weirstrass et on le multiplie par le scalar puis on passe à la forme de 
            # assert x_scalar_twist == ((scalar * G_twist_weirstrass).x*pow(c,-1,p))%p

            Q = curve_weirstrass_twist.point_from_x((x_scalar_twist*c)%p) # on prend la coordonnée x renvoyée x(c*Gx)
            # assert Q == scalar * G_twist_weirstrass
            crt_system_equations=polhig_hellman(G_twist_weirstrass, Q, int(order_twist), prime_decomposition, fast=True, list_prime_avoid=list_prime_avoid)
            break
    return crt_system_equations


if __name__ == "__main__":
    # ========== Curve parameter ==========

    p = 2**192 - 237
    a = -3
    b = 1379137549983732744405137513333094987949371790433997718123
    order = 6277101735386680763835789423072729104060819681027498877478

    # ========== Private key ==========
    scalar = int.from_bytes(os.urandom(24), "big")
    print(f" private key : {scalar}")

    crt_system_equations=break_curve(a,b,p,scalar)
    crt_system_equations+=break_twist(a,b,p,scalar)

    solution,modulo=ChineseRemainder(list(set(crt_system_equations)), True)

    # on s'assure qu'on a dépassé l'ordre de la courbe
    assert modulo>order
    assert scalar==solution%order
    print("toto")


# # to read https://crypto.stackexchange.com/questions/19877/understanding-twist-security-with-respect-to-short-weierstrass-curves
# à regarder https://www.youtube.com/watch?v=g4TP_JukHj4
# https://7rocky.github.io/en/ctf/other/ecsc-2023/twist-and-shout/
