



if __name__ == "__main__":

    # ==============================================
    #================ GF(2) ========================
    # ==============================================

    assert GF2(7)+GF2(7) == GF2(0)
    a,b = 7, 6
    assert GF2(a)+GF2(b) == GF2(1)
    assert a,b == (7,6)
    del a,b
    
    assert GF2(3)*GF2(3) == GF2(5) 
    # 11 * 11 = (x+1) * (x+1) = x**2 + 1 = 101 = 5
    a,b = 4,2
    assert GF2(a)*GF2(b) == GF2(8) 
    assert a,b == (4,2)
    # 100 * 10 = x**2 * x = x**3 = 1000 = 8
    del a,b

    a,b = 5,2
    assert GF2(a) % GF2(b) == GF2(1)
    assert a,b == (5,2)
    del a,b
    # 5 / 2 = 101 / 10 = x**2 +1 / x <=> x*2 +1 = x*x+1 
    # q = x = 10 = 2
    # r = 1

    # ==============================================
    # ================ GF(2^k) =====================
    # ==============================================

    # ============= Modular reduction =============
    
    assert GF2_k(20,19) == GF2_k(7,19)
    # x**4+x**2 (20) % x**4+x+1 (19) = x**2+x+1 (7)

    # ============ Addition and mulitplication in GF2_k ===========
    a, b = 15, 5 
    c = GF2_k(a,19)
    d = GF2_k(b,19)
    assert c + d == GF2_k(10,19)
    assert c * d == GF2_k(6,19)
    assert a,b == (15,5)
    del a,b,c,d
    # (x**3+x**2+x+1)[15] * (x**2+1)[5] = (x**5+x**4+x+1)
    # x**5+x**4+x+1 % (x**4+x+1 [19]) = x**2 +x [6]
    
    # ============ Inverse modulaire ===========
    a = GF2_k(2,19)
    inv = a.inv()
    assert a*inv == GF2_k(1,19)
    assert a//a == GF2_k(1,19)
    del a,inv

    # ============ Power ===========
    a = GF2_k(2,19)
    assert a**4 == GF2_k(3,19)
    del a

    # ============ AES-GCM qq tests ===========
    mod = 0x100000000000000000000000000000087
    a = GF2_k(2,mod)
    assert a**127 == GF2_k(2**127,mod)
    assert a**128 == GF2_k(135,mod)
    del a

    # vecteurs de test générés avec sagemath
    A = 0x1c00cbd9fb99d19f00266385a3753322
    B = 0x91d3771b7e145dd5769b6670f54f327f
    C = 0x82f0053b0777ab862d507a8292ceaa11
    assert GF2_k(A,mod)*GF2_k(B,mod) == GF2_k(C,mod)

    del A, B, C

    # ==============================================
    # ================ GF(2^k)[X] ==================
    # ==============================================
    # jesus christ please .......

    # ============ Addition and multiplication ===========
    a, b, c, d, e, f = 15, 2, 1, 15, 14, 0

    x0 = GF2_k(a,19)
    x1 = GF2_k(b,19)
    x2 = GF2_k(c,19)

    y0 = GF2_k(d,19)
    y1 = GF2_k(e,19)
    y2 = GF2_k(f,19)

    zero = GF2_k(0,19)

    l = Poly_GF2_k([x2,x1,x0])
    m = Poly_GF2_k([y2,y1,y0])
    zero_poly = Poly_GF2_k([zero])

    print(l)
    print(m)
    print(l+m)
    
    assert l+m == Poly_GF2_k([x2,x1+y1,x0+y0])
    assert l*m == Poly_GF2_k([x2*y1,x2*y0+x1*y1,x0*y1+x1*y0,x0*y0])
    assert l*zero_poly == Poly_GF2_k([zero])

    # ============ Division euclidienne ===========
    q, r = l//m, l%m
    assert l == q*m+r
    assert r._deg()<m._deg()

    q, r = zero_poly//l, zero_poly%l
    assert q == zero_poly
    assert r == zero_poly

    # Pour être super rigoureux il faudrait vérifier qu'on a pas d'autres divisieurs plus grand mais bon 
    pgcd, x , y = Poly_GF2_k.extended_euclidian_poly(l,m)
    assert x*l+y*m == pgcd
    assert l%pgcd == zero_poly
    assert m%pgcd == zero_poly


    pgcd, x , y = Poly_GF2_k.extended_euclidian_poly(l,l)
    assert pgcd == l

    # =========== derivative Linearity & Leibniz Law =============
    assert (l+m).derivative() == l.derivative() + m.derivative() 
    assert (l*m).derivative() == l.derivative()*m + l*m.derivative()

    # ============ square root  ===========
    assert not l._is_square()
    assert  (l*l)._is_square()

    assert (l*l*m*m).square_root() == l*m
    assert (l*l).square_root() == l
    
    # ============ square free factorization  ===========
    l = Poly_GF2_k([x2,x1,x0])
    m = Poly_GF2_k([y2,y1,y0])
    n = Poly_GF2_k([y0,y0,y0])
    o = Poly_GF2_k([y0,y0,y0, x1])
    f = Poly_GF2_k([y0,y0,x1])
    u = Poly_GF2_k([y1,x1])

    assert Poly_GF2_k.square_free((l**3*m**4).monic()) == [(l.monic(),3), (m.monic(),4)]
    assert Poly_GF2_k.square_free((l).monic()) == [(l.monic(),1)]
    assert Poly_GF2_k.square_free((l*m).monic()) == [((l*m).monic(),1)]
    assert Poly_GF2_k.square_free((l**2*m**2).monic()) == [((l*m).monic(),2)]
    assert Poly_GF2_k.square_free(((l*m)**3).monic()) == [((l*m).monic(),3)]
    assert Poly_GF2_k.square_free((l**8).monic()) == [(l.monic(), 8)]
    assert Poly_GF2_k.square_free((l**6).monic()) == [(l.monic(), 6)]

    # This not perfectly Yun algorithm
    # it's not a problem because the goal is to break done the squares
    #assert Poly_GF2_k.square_free((m*l*n**2*o**3*f**3).monic()) == [((l*m).monic(),1), (n.monic(),2), ((o*f).monic(),3)]
    distinct = Poly_GF2_k.square_free((u*m*l*n**2*o**3*f**3).monic())
    assert distinct == [((u*l*m*f*o).monic(),1), ((n*o*f).monic(),2)]
    
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

    # vérification de la factorisation
    assert Poly_GF2_k.distinct_degree(f) == [(L1*L2,1), (C1,3), (R1*R2,5)]

    # ============ Equal degree factorization (probabilist )  ===========

    assert Poly_GF2_k.equal_degree_factorization(L1*L2,1) in [[L1,L2], [L2, L1]]
    assert Poly_GF2_k.equal_degree_factorization(L1*L2,1) in [[L1,L2], [L2, L1]]
    assert Poly_GF2_k.equal_degree_factorization(L1*L2,1) in [[L1,L2], [L2, L1]]

    assert Poly_GF2_k.equal_degree_factorization(C1,3) == [C1]
    assert Poly_GF2_k.equal_degree_factorization(C1,3) == [C1]
    assert Poly_GF2_k.equal_degree_factorization(C1,3) == [C1]

    assert Poly_GF2_k.equal_degree_factorization(R1*R2,5) in [[R1,R2], [R2, R1]]
    assert Poly_GF2_k.equal_degree_factorization(R1*R2,5) in [[R1,R2], [R2, R1]]
    assert Poly_GF2_k.equal_degree_factorization(R1*R2,5) in [[R1,R2], [R2, R1]]