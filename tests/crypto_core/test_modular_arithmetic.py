import pytest
from crypto_core.modular_arithmetic import (
    extended_euclidian,
    inverse_modulaire,
    pgcd,
    legendre,
    ChineseRemainder,
)


class TestExtendedEuclidian:
    @pytest.mark.parametrize("a, b, expected_pgcd", [
        (240, 46, 2),
        (17, 5, 1),
        (12, 8, 4),
        (35, 14, 7),
    ])
    def test_returns_correct_gcd(self, a, b, expected_pgcd):
        g, _, _ = extended_euclidian(a, b)
        assert g == expected_pgcd

    @pytest.mark.parametrize("a, b", [
        (240, 46),
        (17, 5),
        (35, 14),
    ])
    def test_bezout_identity(self, a, b):
        # extended euclidian must satisfy g = a*x + b*y
        g, x, y = extended_euclidian(a, b)
        assert a * x + b * y == g


class TestInverseModulaire:
    @pytest.mark.parametrize("a, modulo, expected", [
        (3, 11, 4),     # 3*4 = 12 = 1 mod 11
        (7, 26, 15),    # 7*15 = 105 = 1 mod 26
        (2, 5, 3),      # 2*3 = 6 = 1 mod 5
    ])
    def test_inverse_value(self, a, modulo, expected):
        assert inverse_modulaire(a, modulo) % modulo == expected

    @pytest.mark.parametrize("a, modulo", [
        (3, 11),
        (7, 26),
        (10, 17),
    ])
    def test_inverse_property(self, a, modulo):
        # a * a^(-1) = 1 mod modulo
        inv = inverse_modulaire(a, modulo)
        assert (a * inv) % modulo == 1

    @pytest.mark.parametrize("a, modulo", [
        (4, 8),     # gcd(4,8)=4 != 1
        (6, 9),     # gcd(6,9)=3 != 1
    ])
    def test_raises_when_not_coprime(self, a, modulo):
        with pytest.raises(Exception):
            inverse_modulaire(a, modulo)


class TestPgcd:
    @pytest.mark.parametrize("a, b, expected", [
        (12, 8, 4),
        (17, 5, 1),
        (100, 75, 25),
    ])
    def test_pgcd(self, a, b, expected):
        assert pgcd(a, b) == expected


class TestLegendre:
    @pytest.mark.parametrize("a, p, expected", [
        (2, 7, 1),      # 2 is QR mod 7 (3^2=2)
        (3, 7, 6),      # 3 is non-QR mod 7 → p-1
        (4, 7, 1),      # 4 = 2^2 is QR
    ])
    def test_legendre_symbol(self, a, p, expected):
        assert legendre(a, p) == expected


class TestChineseRemainder:
    @pytest.mark.parametrize("system, expected", [
        ([(2, 5), (3, 11), (5, 17)], (872, 935)),
        ([(2, 3), (3, 5), (2, 7)], (23, 105)),
    ])
    def test_crt_slow(self, system, expected):
        assert ChineseRemainder(system) == expected

    @pytest.mark.parametrize("system, expected", [
        ([(2, 5), (3, 11), (5, 17)], (872, 935)),
        ([(2, 3), (3, 5), (2, 7)], (23, 105)),
    ])
    def test_crt_fast(self, system, expected):
        assert ChineseRemainder(system, fast=True) == expected

    @pytest.mark.parametrize("system", [
        [(2, 4), (3, 8)],     # 4 and 8 not coprime
        [(1, 6), (2, 9)],     # 6 and 9 not coprime
    ])
    def test_raises_when_modulos_not_coprime(self, system):
        with pytest.raises(Exception):
            ChineseRemainder(system)