import sys, os
import random as rd 
from time import time
from sage.all import EllipticCurve, GF, kronecker
from Crypto.Util.number import bytes_to_long, long_to_bytes

from Eliptic_curve import WeierStrass, PointWeirstrass
from Polhig_Hellman import polhig_hellman
from Modular_arithmetic import ChineseRemainder, pgcd


# # to read https://crypto.stackexchange.com/questions/19877/understanding-twist-security-with-respect-to-short-weierstrass-curves
# à regarder https://www.youtube.com/watch?v=g4TP_JukHj4
# https://7rocky.github.io/en/ctf/other/ecsc-2023/twist-and-shout/

# ==============================
# Would be great to reafctor a bit, code not very clean

def dbl(P1,a,b,p):
    X1, Z1 = P1 

    XX = X1**2 % p 
    ZZ = Z1**2 % p
    A = 2 * ((X1 + Z1) ** 2 - XX - ZZ) % p
    aZZ = a * ZZ % p
    X3 = ((XX - aZZ) ** 2 - 2 * b * A * ZZ) % p
    Z3 = (A * (XX + aZZ) + 4 * b * ZZ**2) % p

    return (X3, Z3)

def diffadd(P1, P2, x0, a, b, p):
    X1, Z1 = P1
    X2, Z2 = P2

    X1Z2 = X1 * Z2 % p
    X2Z1 = X2 * Z1 % p
    Z1Z2 = Z1 * Z2 % p
    T = (X1Z2 + X2Z1) * (X1 * X2 + a * Z1Z2) % p
    Z3 = (X1Z2 - X2Z1) ** 2 % p
    X3 = (2 * T + 4 * b * Z1Z2**2 - x0 * Z3) % p

    return (X3, Z3)

def scalarmult(scalar, x0, a, b, p ):
    R0 = (x0, 1)
    R1 = dbl(R0, a, b, p )  # renvoie R0 
    n = scalar.bit_length()
    pbit = 0

    pbit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^ bit # si pbit = bit => pbit =0 else if pbib!=bit => bit =1
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0, a, b, p)
        R0 = dbl(R0, a, b, p)
        pbit = bit

    if bit:
        R0 = R1

    if R0[1] == 0:
        return "Infinity"
    return R0[0] * pow(R0[1], -1, p) % p

def x_coordinate(G:PointWeirstrass, scalar:int):
    return (scalar*G).x

def weirstrass_to_twist(x1,y1,c,a,b,p):
    x = (x1*pow(c,-1,p))%p
    y = (y1*pow(c,-1,p)**2)%p
    return x, y

def twist_to_weirstrass(x,y,c,a,b,p):
    return (x*c)%p, (y*c**2)%p

# ========== Pohlig Helman on breakable prime power order of Weirstrass curve ==========
def break_curve(a:int,b:int,p:int,interface,scalar:int=None,limit_prime_pohlig:int=10**13):

    E  = EllipticCurve(GF(p), [a, b])
    G = E.gens()
    curve_weirstrass = WeierStrass(a, b, p)
    G_weirstrass = PointWeirstrass(curve_weirstrass, int(tuple(G[0])[0]), int(tuple(G[0])[1]))
    print(f"G_weirstrass :{G_weirstrass}")
    order = E.order()
    print(f"order curve:{order}")
    prime_decomposition = order.factor()
    prime_decomposition =  [(int(k[0]),int(k[1])) for k in list(prime_decomposition)]
    list_prime_avoid = list(map(lambda x:x[0],list(filter(lambda x:x[0]>limit_prime_pohlig,prime_decomposition))))

    print(f"EllipticCurve(K, [a, b]) order :{prime_decomposition}")

    # S'assurer ABSOLUMENT que G_weirstrass.x est sur la courbe de Weirstrass
    if interface==scalarmult:
        x_scalar_weirstrass = int(interface(scalar, G_weirstrass.x, a, b, p ))
    else:
        x_scalar_weirstrass = interface(G_weirstrass.x)

    Q = curve_weirstrass.point_from_x((x_scalar_weirstrass)%p) 

    crt_system_equations=polhig_hellman(G_weirstrass, Q, int(order), prime_decomposition, fast=True, list_prime_avoid=list_prime_avoid)
    return G_weirstrass, x_scalar_weirstrass, crt_system_equations

def break_twist(a:int,b:int,p:int,interface,scalar:int=None,limit_prime_pohlig:int=10**13):
    
    # we search c such that c is not a square 
    for c in range(-1, 50):
        if kronecker(c,p)==-1:
            Et = EllipticCurve(GF(p), [c**2*a, c**3*b])
            order_twist = Et.order()
            print(f"order_twist:{order_twist},c:{c}" )


            prime_decomposition = order_twist.factor()
            prime_decomposition =  [(int(k[0]),int(k[1])) for k in list(prime_decomposition)]
            list_prime_avoid = list(map(lambda x:x[0],list(filter(lambda x:x[0]>limit_prime_pohlig,prime_decomposition))))

            print(f"EllipticCurve(GF(p), [c**2*a, c**3*b]) order (c:{c} non square over Fp) :{prime_decomposition}")

            G_twist_sage = Et.gens()
            curve_weirstrass_twist = WeierStrass(c**2*a, c**3*b,p)
            G_twist_weirstrass = PointWeirstrass(curve_weirstrass_twist, int(tuple(G_twist_sage[0])[0]), int(tuple(G_twist_sage[0])[1]))
            print(f"G_twist_weirstrass :{G_twist_weirstrass}")

            x,y = weirstrass_to_twist(G_twist_weirstrass.x, G_twist_weirstrass.y, c, a, b, p)

            # S'assurer ABSOLUMENT que x est sur le twist
            if interface==scalarmult:
                x_scalar_twist = int(interface(scalar, x, a, b, p ))
            else:
                x_scalar_twist = interface(x)

            Q = curve_weirstrass_twist.point_from_x((x_scalar_twist*c)%p) # on prend la coordonnée x renvoyée x(c*Gx)
            crt_system_equations=polhig_hellman(G_twist_weirstrass, Q, int(order_twist), prime_decomposition, fast=True, list_prime_avoid=list_prime_avoid)
            
            break
        else:
            raise Exception("Not a single non square c for the twist was found")

    return G_twist_weirstrass, x_scalar_twist, crt_system_equations

def crt_system_equation_solution(crt_system_equations1, crt_system_equations2, order, G_weirstrass, x_scalar_weirstrass):
    solution1,modulo1=ChineseRemainder(list(set(crt_system_equations1+crt_system_equations2)), True)
    assert modulo1>order

 
    if x_coordinate(G_weirstrass, solution1)==x_scalar_weirstrass: # k%order/k%order_twist => solution CRT k
        solution=solution1%order
        case=1
    elif x_coordinate(G_weirstrass, (-solution1%modulo1)%order)==x_scalar_weirstrass: # -k%order/-k%order_twist => solution CRT -k
        solution=((-solution1%modulo1))%order
        case=2
    else: 
        # sinon ca veut dire qu'on a deux systèmes incompatibles autrement dit l'un fait 
        # (-k%order et k%order_twist) ou inversement (k%order et -k%order_twist)
        # on va inverser le système de congruences pour k%order afin d'avoir un cohérence de signe 
        crt_system_equations1_neg = list(map(lambda k:((-k[0])%k[1], k[1]),crt_system_equations1))
        solution2,modulo2=ChineseRemainder(list(set(crt_system_equations1_neg+crt_system_equations2)), True)
        if x_coordinate(G_weirstrass, solution2)==x_scalar_weirstrass: #-k%order/k%order_twist => solution CRT k
            solution=solution2%order
            case=3
        else: #k%order/-k%order_twist => solution CRT -k
            solution=((-solution2%modulo2))%order
            case=4

    print(f"solution({case}) : {solution}")   
    assert (solution*G_weirstrass).x==x_scalar_weirstrass
    assert x_coordinate(G_weirstrass,solution)==x_scalar_weirstrass

    return solution

if __name__ == "__main__":
    
    t1=time()

    # ========== Curve parameter ==========
    p = 2**192 - 237
    a = -3
    b = 1379137549983732744405137513333094987949371790433997718123
    order = 6277101735386680763835789423072729104060819681027498877478
    limit_prime_pohlig = 10**13

    # ========== Private key ==========
    scalar = int.from_bytes(os.urandom(24), "big")
    scalar = min(scalar % order, (order - scalar) % order)

    print(f" private key : {scalar}")

    # scalar = 2948306227418300673296973821543438842352265484304963330490  # solution 1
    # scalar = 1191366691553679168291613729018049848093918470094984820357  # solution 2
    # scalar = 2522942703444388320672704179922209746951556402929845453750  # solution 3
    # scalar = 480741244806338836306541178899819119025113411194700564656   # solution 4 

    # ========== Polhig Hellamn on Curve and Twist on breakable power ==========

    interface = scalarmult

    G_weirstrass, x_scalar_weirstrass, crt_system_equations1=break_curve(a,b,p,interface,scalar,limit_prime_pohlig)
    G_twist_weirstrass, x_scalar_twist, crt_system_equations2=break_twist(a,b,p,interface,scalar,limit_prime_pohlig)  

    # ========== Avant polhig Hellman on fait un choix car quand on nous renvoie l coordonée x on peut choisir P(x, +/y) avec tonneli
    # ==========   on doit donc rendre coherent le système d'équation pour CRT ==========  

    # on s'assure de pas avoir de sous groupe en doublons pour le CRT 
    solution = crt_system_equation_solution(crt_system_equations1, crt_system_equations2, order, G_weirstrass, x_scalar_weirstrass)
    
    assert scalar==solution
    

