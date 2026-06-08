import pytest
from crypto_core.galois_field import GF2, GF2_k, Poly_GF2_k


class TestGF2:

    @pytest.mark.parametrize("x, y, expected", [
        (7, 7, 0),
        (7, 6, 1),
    ])
    def test_addition(self, x, y, expected):
        assert GF2(x)+GF2(y) == GF2(expected)
    
    @pytest.mark.parametrize("x, y, expected", [
        (3, 3, 5),
        (4, 2, 8),
    ])
    def test_multiplication(self, x, y, expected):
        assert GF2(x)*GF2(y) == GF2(expected)

    @pytest.mark.parametrize("x, y, expected", [
        (5, 2, 1),
    ])
    def test_div_euclidienne(self, x, y, expected):
        assert GF2(x) % GF2(y) == GF2(expected)
        # 5 / 2 = 101 / 10 = x**2 +1 / x <=> x*2 +1 = x*x+1 
        # q = x = 10 = 2
        # r = 1

class TestGF2_k:
    @pytest.mark.parametrize("x1, x2, mod", [
        (20, 7, 19),
    ])
    def test_reduction_modulaire(self, x1, x2, mod):
        # x**4+x**2 (20) % x**4+x+1 (19) = x**2+x+1 (7)
        assert GF2_k(x1, mod) == GF2_k(x2, mod)

    @pytest.mark.parametrize("a, b, mod, expected", [
        (15, 5, 19, 10),
    ])
    def test_addition(self, a, b, mod, expected):
        assert GF2_k(a, mod) + GF2_k(b, mod) == GF2_k(expected, mod)

    @pytest.mark.parametrize("a, b, mod, expected", [
        (15, 5, 19, 6),
        pytest.param(0x1c00cbd9fb99d19f00266385a3753322, 0x91d3771b7e145dd5769b6670f54f327f, 0x100000000000000000000000000000087, 0x82f0053b0777ab862d507a8292ceaa11, id="AES-GCM sagemath"),
    ])
    def test_multiplication(self, a, b, mod, expected):
        # (x**3+x**2+x+1)[15] * (x**2+1)[5] = (x**5+x**4+x+1)
        # x**5+x**4+x+1 % (x**4+x+1 [19]) = x**2 +x [6]
        assert GF2_k(a, mod) * GF2_k(b, mod) == GF2_k(expected, mod)

    @pytest.mark.parametrize("a, mod, expected", [
        (2, 19, 9),
    ])
    def test_inverse(self, a, mod, expected):
        assert GF2_k(a, mod).inv() == GF2_k(expected, mod)

    @pytest.mark.parametrize("a, mod, power, expected", [
        (2, 19, 4, 3),
        pytest.param(2, 0x100000000000000000000000000000087, 127, 2**127, id="Puissance AES GCM 127"),
        pytest.param(2, 0x100000000000000000000000000000087, 128, 135, id="Puissance AES GCM 128"),
    ])
    def test_puissance(self, a, mod, power, expected):
        assert GF2_k(a, mod) ** power ==  GF2_k(expected, mod)



class TestPolyGF2kArithmetic:
    @pytest.fixture
    def polys(self):
        
        # on va fixer l, m, le polynome zero
        a, b, c, d, e, f = 15, 2, 1, 15, 14, 0

        x0 = GF2_k(a,19)
        x1 = GF2_k(b,19)
        x2 = GF2_k(c,19)

        y0 = GF2_k(d,19)
        y1 = GF2_k(e,19)
        y2 = GF2_k(f,19)

        l = Poly_GF2_k([x2, x1, x0])
        m = Poly_GF2_k([y2, y1, y0])

        zero_poly = Poly_GF2_k([GF2_k(0, 19)])

        return l, m, zero_poly, (x0, x1, x2), (y0, y1, y2)

    def test_addition(self, polys):
        l, m, _, (x0, x1, x2), (y0, y1, y2) = polys
        assert l + m == Poly_GF2_k([x2, x1+y1, x0+y0])

    def test_multiplication(self, polys):
        l, m, _, (x0, x1, x2), (y0, y1, y2) = polys
        assert l * m == Poly_GF2_k([x2*y1,x2*y0+x1*y1,x0*y1+x1*y0,x0*y0])

    def test_multiplication_zero(self, polys):
        l, m, zero_poly, _, _ = polys
        assert l * zero_poly == zero_poly

    def test_division_euclidienne(self, polys):
        l, m, zero_poly, _, _ = polys
        q, r = l//m, l%m
        assert l == q*m+r
        assert r._deg()<m._deg()

    def test_division_euclidienne_zero_poly(self, polys):
        l, _, zero_poly, _, _ = polys
        q, r = zero_poly//l, zero_poly%l
        assert q == zero_poly
        assert r == zero_poly

    def test_pgcd(self, polys):
        l, m, zero_poly, _, _ = polys
        pgcd, x , y = Poly_GF2_k.extended_euclidian_poly(l,m)
        assert x*l+y*m == pgcd
        assert l%pgcd == zero_poly
        assert m%pgcd == zero_poly

    def test_pgcd_same_polynome(self, polys):
        l, _, _, _, _ = polys
        pgcd, x , y = Poly_GF2_k.extended_euclidian_poly(l,l)
        assert pgcd == l

    def test_derivative_linearity(self, polys):
        l, m, _, _, _ = polys
        assert (l+m).derivative() == l.derivative() + m.derivative() 

    def test_derivative_libniz(self, polys):
        l, m, _, _, _ = polys
        assert (l*m).derivative() == l.derivative()*m + l*m.derivative()

    def test_is_square_root(self, polys):
        l, _, _, _, _ = polys
        assert not l._is_square()
        assert  (l*l)._is_square()
    
    def test_square_root(self, polys):
        l, m, _, _, _ = polys
        assert (l*l*m*m).square_root() == l*m
        assert (l*l).square_root() == l

class TestPolyGF2kSquareFree:
    @pytest.fixture
    def factors(self):
        x0, x1, x2 = GF2_k(15, 19), GF2_k(2, 19), GF2_k(1, 19)
        y0, y1 = GF2_k(15, 19), GF2_k(14, 19)

        l = Poly_GF2_k([x2, x1, x0])
        m = Poly_GF2_k([GF2_k(0, 19), y1, y0])
        n = Poly_GF2_k([y0, y0, y0])
        o = Poly_GF2_k([y0, y0, y0, x1])
        f = Poly_GF2_k([y0, y0, x1])
        u = Poly_GF2_k([y1, x1])
        return l, m, n, o, f, u

    def test_square_free(self, factors):
        l, m, n, o, f, u = factors

        assert Poly_GF2_k.square_free((l**3*m**4).monic()) == [(l.monic(),3), (m.monic(),4)]
        assert Poly_GF2_k.square_free((l).monic()) == [(l.monic(),1)]
        assert Poly_GF2_k.square_free((l*m).monic()) == [((l*m).monic(),1)]
        assert Poly_GF2_k.square_free((l**2*m**2).monic()) == [((l*m).monic(),2)]
        assert Poly_GF2_k.square_free(((l*m)**3).monic()) == [((l*m).monic(),3)]
        assert Poly_GF2_k.square_free((l**8).monic()) == [(l.monic(), 8)]
        assert Poly_GF2_k.square_free((l**6).monic()) == [(l.monic(), 6)]

        # attention c'est pas yun
        distinct = Poly_GF2_k.square_free((u*m*l*n**2*o**3*f**3).monic())
        assert distinct == [((u*l*m*f*o).monic(),1), ((n*o*f).monic(),2)]

class TestEqualDistinct_degree:
    @pytest.fixture
    def irreducible(self):
        # ============ Distinct free factorization  ===========
        one = GF2_k(1,19)
        zero = GF2_k(0,19)

        X = Poly_GF2_k([one, zero])  # MSB-first

        # génération de polynome irreductile dans GF(2**4) de divers degré

        # degré 1
        L1 = X
        L2 = X + Poly_GF2_k([one])

        # degré 3
        C1 = X**3 + X + Poly_GF2_k([one])

        # degré 5
        R1 = X**5 + X**2 + Poly_GF2_k([one])
        R2 = X**5 + X**3 + Poly_GF2_k([one])

        # produit des facteurs irréductibles
        f = (L1 * L2 * C1 * R1*R2).monic()
        return L1, L2, C1, R1, R2, f

    def test_distinct_degree_factorization(self, irreducible):
        L1, L2, C1, R1, R2, f = irreducible

        # vérification de la factorisation distinct degree
        assert Poly_GF2_k.distinct_degree(f) == [(L1*L2,1), (C1,3), (R1*R2,5)]

    def test_equal_degree_factorization(self, irreducible):
        L1, L2, C1, R1, R2, _ = irreducible
        
        # vérification de la factorisation equal degree
        assert Poly_GF2_k.equal_degree_factorization(L1*L2,1) in [[L1,L2], [L2, L1]]
        assert Poly_GF2_k.equal_degree_factorization(C1,3) == [C1]
        assert Poly_GF2_k.equal_degree_factorization(R1*R2,5) in [[R1,R2], [R2, R1]]
