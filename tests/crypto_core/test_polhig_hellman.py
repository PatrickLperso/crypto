import pytest

from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from crypto_core.polhig_hellman import (brute_force, random_function, progress_filename, save_progress_file, pollard_rho, polhig_hellman)

class TestPrivateKeyBruteForce:
    @pytest.fixture
    def point_curve(self):
        curve1=WeierStrass(1001, 75, 7919)
        order_curve=7889

        P=PointWeirstrass(curve1, 4023,6036)
        Q=2000*P

        return curve1, order_curve, P, Q
    
    def test_bruteforce(self, point_curve):
        curve1, order_curve, P, Q = point_curve

        assert 2000==brute_force(P, Q, order_curve)

    def test_pollard(self, point_curve):
        curve1, order_curve, P, Q = point_curve
        
        solution = pollard_rho(P, Q, order=order_curve, init = 0, reprise_file=False, save_progress=False, max_iterations=order_curve)
        while solution is None:
            k+=1
            print(f"collision non inversible : n°{k}")
            solution = pollard_rho(P, Q, order=order_curve, init = k, reprise_file=False, save_progress=False,  max_iterations=order_curve)
        assert Q==solution * P

    def test_polhig_hellamnn(self, point_curve):
        curve1, order_curve, P, _ = point_curve

        Q=PointWeirstrass(curve1, 4135,3169)

        order=order_curve
        order_prime_decomposition=[(7,3),(23,1)]

        solution,modulo=polhig_hellman(P, Q, order, order_prime_decomposition, fast=False)
        assert solution,modulo == (4334,7889)
        assert solution*P == Q
        assert (10*modulo+solution)*P == Q