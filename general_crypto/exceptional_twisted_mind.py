import sys, os
import random as rd 
from time import time
from sage.all import EllipticCurve, GF, kronecker, Integer
from Crypto.Util.number import bytes_to_long, long_to_bytes

from Eliptic_curve import WeierStrass, PointWeirstrass
from Polhig_Hellman import polhig_hellman
from Modular_arithmetic import ChineseRemainder, pgcd

# Parameters
modulus = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
a = -3
b = 152961
order = 115792089237316195423570985008687907853233080465625507841270369819257950283813


def dbl(P1):
    X1, Z1 = P1

    XX = X1**2 % modulus
    ZZ = Z1**2 % modulus
    A = 2 * ((X1 + Z1) ** 2 - XX - ZZ) % modulus
    aZZ = a * ZZ % modulus
    X3 = ((XX - aZZ) ** 2 - 2 * b * A * ZZ) % modulus
    Z3 = (A * (XX + aZZ) + 4 * b * ZZ**2) % modulus

    return (X3, Z3)


def diffadd(P1, P2, x0):
    X1, Z1 = P1
    X2, Z2 = P2

    X1Z2 = X1 * Z2 % modulus
    X2Z1 = X2 * Z1 % modulus
    Z1Z2 = Z1 * Z2 % modulus
    T = (X1Z2 + X2Z1) * (X1 * X2 + a * Z1Z2) % modulus
    Z3 = (X1Z2 - X2Z1) ** 2 % modulus
    X3 = (2 * T + 4 * b * Z1Z2**2 - x0 * Z3) % modulus

    return (X3, Z3)


def swap(bit, P1, P2):
    if bit == 1:
        P1, P2 = P2, P1
    return P1, P2


def scalarmult(scalar, x0):
    R0 = (x0, 1)
    R1 = dbl(R0)
    n = scalar.bit_length()
    pbit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^ bit
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0)
        R0 = dbl(R0)
        pbit = bit

    if bit:
        R0 = R1

    if GCD(R0[1], modulus) != 1:
        return "Infinity"
    return R0[0] * inverse(R0[1], modulus) % modulus


class Challenge:
    def __init__(self):
        self.before_input = f"Welcome!\nYou can submit only {LIMIT} elliptic curve point (x coordinate only).\nYou have {TIMEOUT} seconds to submit the private key in decimal format.\n"
        self.timeout_secs = TIMEOUT
        privkey = int.from_bytes(os.urandom(32), "big")
        self.privkey = min(privkey % order, (order - privkey) % order)
        self.attempts_remaining = 1

    def challenge(self, your_input):
        if "option" not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input["option"] == "get_pubkey":
            if self.attempts_remaining == 0:
                return {
                    "error": "You cannot submit a point anymore. Now, please submit the private key."
                }

            x0 = int(your_input["x0"])
            pubkey = scalarmult(self.privkey, x0)
            self.attempts_remaining -= 1
            return {"pubkey": pubkey}

        elif your_input["option"] == "get_flag":
            guess = your_input["privkey"]
            if guess % order == self.privkey:
                return {
                    "message": "Congratulations, you found my private key.",
                    "flag": FLAG,
                }
            else:
                return {"error": "Sorry, this is not my private key."}
        else:
            return {"error": "You must send an option to this server"}

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