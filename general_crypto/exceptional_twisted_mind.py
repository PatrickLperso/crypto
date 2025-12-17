import sys, os
import random as rd 
from time import time
from sage.all import EllipticCurve, GF, kronecker, Integer
from Crypto.Util.number import bytes_to_long, long_to_bytes

from Eliptic_curve import WeierStrass, PointWeirstrass
from Polhig_Hellman import polhig_hellman
from Modular_arithmetic import ChineseRemainder, pgcd

if __name__ == "__main__":
    modulo = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
    
    p=115792089237316195423570985008687907853269984665640564039457584007913129639747
    assert p**2 == modulo

    Dans EllipticCurve(GF(p), [a, b])
    a = -3
    b = 152961

    # order is prime incassable de EllipticCurve(GF(p), [a, b])
    order = 115792089237316195423570985008687907853233080465625507841270369819257950283813
    assert Integer(order).is_prime()
    

    # mais de order de la courbe EllipticCurve(GF(modulo), [a, b])
    order = 13407807929942597099574024998205846127479365820592393377723561443721764030030007789328664657413742229457939415221861291144822273976189790359454910841779279
    assert order == 115792089237316195423570985008687907853306888865655620237644798196568308995683*115792089237316195423570985008687907853233080465625507841270369819257950283813

    E = EllipticCurve(GF(modulo), [a, b])
    Et = EllipticCurve(GF(p), [c**2*a, c**3*b])
    E2 = EllipticCurve(GF(p**2), [a, b])