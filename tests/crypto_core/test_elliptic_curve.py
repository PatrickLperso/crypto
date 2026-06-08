import pytest
from hashlib import sha256  # adapte l'import à ton module réel
from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass, Montgomery, ECDH

@pytest.fixture
def curve():
    """curve: y^2 = x^3 + 497x + 1768 over GF(9739)."""
    return WeierStrass(497, 1768, 9739)


@pytest.fixture
def generator(curve):
    """Base point G on the starter curve."""
    return PointWeirstrass(curve, 1804, 5368)


class TestPointInverseAndInfinity:
    def test_negation_flips_y_coordinate(self, curve):
        P = PointWeirstrass(curve, 8045, 6936)
        assert -P == PointWeirstrass(curve, 8045, 2803)

    def test_self_subtraction_is_infinity(self, curve):
        P = PointWeirstrass(curve, 8045, 6936)
        assert P - P == PointWeirstrass(curve)


class TestPointAddition:
    def test_add_two_distinct_points(self, curve):
        X = PointWeirstrass(curve, 5274, 2841)
        Y = PointWeirstrass(curve, 8669, 740)
        assert X + Y == PointWeirstrass(curve, 1024, 4440)

    def test_point_doubling(self, curve):
        X = PointWeirstrass(curve, 5274, 2841)
        assert X + X == PointWeirstrass(curve, 7284, 2107)

    def test_chained_addition(self, curve):
        P = PointWeirstrass(curve, 493, 5564)
        Q = PointWeirstrass(curve, 1539, 4742)
        R = PointWeirstrass(curve, 4403, 5202)
        assert P + P + Q + R == PointWeirstrass(curve, 4215, 2162)


class TestScalarMultiplication:
    def test_scalar_mult_1337(self, curve):
        X = PointWeirstrass(curve, 5323, 5438)
        assert 1337 * X == PointWeirstrass(curve, 1089, 6931)

    def test_scalar_mult_7863(self, curve):
        P = PointWeirstrass(curve, 2339, 2213)
        assert 7863 * P == PointWeirstrass(curve, 9467, 2742)


class TestECDH:
    def test_shared_secret_sha1_from_public_point(self, curve):
        alice_key = PointWeirstrass(curve, 815, 3190)
        secret = 1829
        shared = ECDH.shared_secret_sha1(secret, alice_key)
        assert shared == "80e5212754a824d3a4aed185ace4f9cac0f908bf"

    def test_decrypt_flag_from_shared_x_coordinate(self, curve):
        secret = 6534
        alice_key = curve.point_from_x(4726)
        shared_point = ECDH.share_point_from_point(secret, alice_key)
        iv = "cd9da9f1c60925922377ea952afc212c"
        ciphertext = "febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8"
        flag = ECDH.decrypt_flag(shared_point.x, iv, ciphertext)
        assert flag == "crypto{3ff1c1ent_k3y_3xch4ng3}"


class TestMontgomeryCurve:
    def test_scalar_mult_on_curve25519(self):
        """Curve25519: B y^2 = x^3 + 486662 x^2 + x over GF(2^255 - 19)."""
        curve = Montgomery(1, 486662, (2**255) - 19)
        G = curve.point_from_x(9)
        Q = 21130179955454 * G
        assert Q.x == 49231350462786016064336756977412654793383964726771892982507420921563002378152