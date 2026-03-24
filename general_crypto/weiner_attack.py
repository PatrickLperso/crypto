import numpy as np
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import math


def test_cle(d, e, N):
    if (d==0):
        return False
    else:
        c = pow(12, e, N)
        return 12 == pow(c,d, N)

def Weiner(e, N):
    # un petit d tel que ed = 1 mod phi (n)
    # alors si
    # |e/N - k/d| < 1/(2*d**2)
    # alors e/N est tres proche de k/d et
    # donc k/d doit se trouver dans la liste des convergents d
    # u développement en fractions continues de e/N
    # e/N = a0 + 1/a1 = a0 + 1/(a1 + 1/a2)

    # https://bibnum.publimath.fr/IDI/IDI05026.pdf

    # bon normalement verifier plus serisuement les conditions de l'attaque
    if e>N:
        raise Exception

    # coefficients d'initialisation
    k_i_2 = 0
    d_i_2 = 1

    k_i_1 = 1
    d_i_1 = 0 

    a, b = e, N

    while (b>0):
        print(b)
        quotient = a//b
        a, b= b, a%b

        k_current = quotient * k_i_1 + k_i_2
        d_current = quotient * d_i_1 + d_i_2

        # ===== Formules pour les fractions continues =========== 
        
        # k_i =  a_i * k_(i-1) + k_(i-2)
        # ===    ========================
        # d_i =  d_i * k_(i-1) + d_(i-2)

        k_i_2,k_i_1 = k_i_1, k_current
        d_i_2,d_i_1 = d_i_1, d_current

        if test_cle(d_i_1, e, N):
            break

    return d_i_1

if __name__ == "__main__":
    
    e = 0x9ab58dbc8049b574c361573955f08ea69f97ecf37400f9626d8f5ac55ca087165ce5e1f459ef6fa5f158cc8e75cb400a7473e89dd38922ead221b33bc33d6d716fb0e4e127b0fc18a197daf856a7062b49fba7a86e3a138956af04f481b7a7d481994aeebc2672e500f3f6d8c581268c2cfad4845158f79c2ef28f242f4fa8f6e573b8723a752d96169c9d885ada59cdeb6dbe932de86a019a7e8fc8aeb07748cfb272bd36d94fe83351252187c2e0bc58bb7a0a0af154b63397e6c68af4314601e29b07caed301b6831cf34caa579eb42a8c8bf69898d04b495174b5d7de0f20cf2b8fc55ed35c6ad157d3e7009f16d6b61786ee40583850e67af13e9d25be3
    c = 0x3f984ff5244f1836ed69361f29905ca1ae6b3dcf249133c398d7762f5e277919174694293989144c9d25e940d2f66058b2289c75d1b8d0729f9a7c4564404a5fd4313675f85f31b47156068878e236c5635156b0fa21e24346c2041ae42423078577a1413f41375a4d49296ab17910ae214b45155c4570f95ca874ccae9fa80433a1ab453cbb28d780c2f1f4dc7071c93aff3924d76c5b4068a0371dff82531313f281a8acadaa2bd5078d3ddcefcb981f37ff9b8b14c7d9bf1accffe7857160982a2c7d9ee01d3e82265eec9c7401ecc7f02581fd0d912684f42d1b71df87a1ca51515aab4e58fab4da96e154ea6cdfb573a71d81b2ea4a080a1066e1bc3474
    N = 0xb8af3d3afb893a602de4afe2a29d7615075d1e570f8bad8ebbe9b5b9076594cf06b6e7b30905b6420e950043380ea746f0a14dae34469aa723e946e484a58bcd92d1039105871ffd63ffe64534b7d7f8d84b4a569723f7a833e6daf5e182d658655f739a4e37bd9f4a44aff6ca0255cda5313c3048f56eed5b21dc8d88bf5a8f8379eac83d8523e484fa6ae8dbcb239e65d3777829a6903d779cd2498b255fcf275e5f49471f35992435ee7cade98c8e82a8beb5ce1749349caa16759afc4e799edb12d299374d748a9e3c82e1cc983cdf9daec0a2739dadcc0982c1e7e492139cbff18c5d44529407edfd8e75743d2f51ce2b58573fea6fbd4fe25154b9964d


    d = Weiner(e, N)
    assert b'crypto{s0m3th1ng5_c4n_b3_t00_b1g}' == long_to_bytes(pow(c, d, N))