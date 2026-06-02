from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

from sage.all import PolynomialRing, Zmod, RealField
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse
import random as rd

FLAG =      b"crypto{???????????????????????????????????}"

def pad100(msg):
    return msg + b'\x00' * (100 - len(msg))

def generate_message(msg):
    key = RSA.generate(1024, e=3)
    n, e = key.n, key.e

    m = bytes_to_long(pad100(msg))
    c = pow(m, e, n)
    return n,e,c


def recover(n, e, c, length=None):
    R = PolynomialRing(Zmod(n), names=('x'))
    x = R.gen()

    # on ne connait pas la longueur du message à l'interieur des paranthèses
    for k in range(1, 100 - 7 - 1):
        if length==k or length==None:
            decalage = 100 - 7 - k

            FLAG_mask = b"crypto{" + k * b"\x00"  + b"}"
            mask_padded = bytes_to_long(pad100(FLAG_mask))

            f = (2**(decalage*8)*x + mask_padded)**e - c

            roots = f.monic().small_roots(beta=1.0, epsilon=0.03)
            if len(roots)!=0:
                flag = long_to_bytes(int(roots[0]))
                print(b"crypto{" + flag + b"}")
                return b"crypto{" + flag + b"}"


if __name__ == "__main__":
    # checker les histoires de parmaetres de la lattice notamment bet et epsilon
    n = 95341235345618011251857577682324351171197688101180707030749869409235726634345899397258784261937590128088284421816891826202978052640992678267974129629670862991769812330793126662251062120518795878693122854189330426777286315442926939843468730196970939951374889986320771714519309125434348512571864406646232154103
    e = 3
    c = 63476139027102349822147098087901756023488558030079225358836870725611623045683759473454129221778690683914555720975250395929721681009556415292257804239149809875424000027362678341633901036035522299395660255954384685936351041718040558055860508481512479599089561391846007771856837130233678763953257086620228436828

    length = 35
    flag = recover(n, e, c, length)

    assert flag == b'crypto{n0n_574nd4rd_p4d_c0n51d3r3d_h4rmful}'

    # ====================== Local test ===============
    # inconnu = bytes([rd.randint(1,127) for _ in range(100 - 7 -1)])

    # for k in range(1, len(inconnu)):
    #     msg = b"crypto{" + inconnu[:k] + b"}"

    #     n, e, c = generate_message(msg)
    #     flag = recover(n, e, c)
        # assert flag == msg

        