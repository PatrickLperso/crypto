import pytest
from crypto_core.polhig_hellman_dl import (
    brute_force,
    random_function,
    pollard_rho,
    order_g_f,
    polhig_hellman,
)


class TestBruteForce:
    @pytest.mark.parametrize("g, key, p", [
        (2, 5, 23),      # 2^5 = 32   = 9  mod 23
        (3, 7, 17),      # 3^7 = 2187 = 11 mod 17
        (5, 3, 23),      # 5^3 = 125  = 10 mod 23
    ])
    def test_finds_discrete_log(self, g, key, p):
        h = pow(g, key, p)
        # order = p-1 ici (g générateur ou pas, on borne par p-1)
        found = brute_force(h, g, p - 1, p)
        assert pow(g, found, p) == h

    def test_raises_when_not_found(self):
        # h jamais atteignable par g dans [0, order]
        with pytest.raises(Exception):
            brute_force(h=999, g=2, order=3, p=23)


class TestPollardRhoModP:
    @pytest.mark.parametrize("g, key, p, order", [
        (1242, 750, 2039, 1019),     #  on se place expres dans un sous groupe d'ordre premier avec g = 1242
    ])
    def test_recovers_discrete_log(self, g, key, p, order):
        h = pow(g, key, p)
        a = pollard_rho(h, g, order, p, init=0)
        # pollard rho peut tomber sur collision non inversible (a=None) → on retente
        k = 0
        while a is None and k < 5:
            k += 1
            a = pollard_rho(h, g, order, p, init=k)
        
        assert a is not None
        assert pow(g, a, p) == h


class TestOrderGf:
    def test_order_of_generator(self):
        # 3 est générateur de (Z/7Z)* donc son ordre est 6 = 2*3
        p = 7
        order_decomp = [(2, 1), (3, 1)]
        decomp, order_g = order_g_f(3, p, order_decomp)
        assert order_g == 6

    def test_order_of_non_generator(self):
        # 2 mod 7 : 2^1=2, 2^2=4, 2^3=1 → ordre 3
        p = 7
        order_decomp = [(2, 1), (3, 1)]
        decomp, order_g = order_g_f(2, p, order_decomp)
        assert order_g == 3


class TestPolhigHellmanModP:
    @pytest.mark.parametrize("g, key, p", [
        (2, 1234, 268435459),   # le cas du __main__
    ])
    def test_recovers_key(self, g, key, p):
        h = pow(g, key, p)
        solution = polhig_hellman(h, g, p, fast=True)
        assert solution[0] % (p - 1) == key % (p - 1)

    def test_raises_when_p_not_prime(self):
        with pytest.raises(Exception):
            polhig_hellman(h=10, g=2, p=100)  # 100 pas premier

