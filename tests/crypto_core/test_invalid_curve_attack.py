import pytest
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad

from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from crypto_core.invalid_curve_attack import (
    Server,
    Challenge,
    key_exchange_attack,
    key_uncipher,
    generate_invalid_curves,
    bruteforce_key,
    bruteforce_aes,
    bruteforce_sign_crt,
    FLAG,
)
       
class TestInvalidCurve: 
    @pytest.fixture
    def params(self):
        # ================== Courbe et paramètre et initalisation du challenge ===============
        p = 17880403
        a = 12569007
        b = 7723304
        order = 17874127

        curve = WeierStrass(a,b,p)
        G = PointWeirstrass(curve, 10268612,24984)
        challenge = Challenge(curve, G)
        return a, b, p, order, curve, G, challenge

    @pytest.mark.parametrize("min_order_bruteforce, max_order_bruteforce, bmax", [
        (10, 500, 50),
        (100, 200, 50),
    ])
    def test_generation_invlid_curve(self, params, min_order_bruteforce, max_order_bruteforce, bmax):
        a, b, p, order, curve, G, challenge = params

        # ================== Génération des courbes vulnérables ===============
        # on une limite min pour ne pas avoir à bruteforce un système CRT trop complexe à la fin (on aura toujours k ou -k possible)
        # donc éliminer les nombres premiers trop petits permet de s'assurer que le brutefroce du CRT à la fin ne sera pas trop gourmand 
        # si 15 nombre premiers 2**15 systmes du CRT possibles si 20 2**20 etc ..
       
        primes_curves, b_primes=generate_invalid_curves(a,p,order,min_order_bruteforce=min_order_bruteforce, max_order_bruteforce=max_order_bruteforce, bmax=bmax)
        assert len(primes_curves.keys()) < bmax
        product = 1 
        for k in  primes_curves.keys():
            product *= k ** primes_curves[k]["power"]
            assert k < max_order_bruteforce
            assert k > min_order_bruteforce
        assert product > order
