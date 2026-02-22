import random as rd

class GF2:
    def __init__(self,x:int):
        assert type(x) == int
        self.x = x

    def __str__(self):
        res =[]
        deg = GF2._deg(self.x)
        for index, k in enumerate(bin(self.x)[2:]):
            if k =="1":
                if index < deg -1:
                    res.append(f"x^{deg - index}")
                elif deg-1 == index:
                    res.append(f"x")
                else:
                    res.append(f"1")
        if len(res) == 0:
            res = "0"
        else:
            res = "+".join(res)
        return res

    def __repr__(self):
        return self.__str__()

    def _deg(x):
        return x.bit_length() - 1

    def __eq__(self,other):
        assert type(other) == GF2
        return self.x == other.x

    def __add__(self,other):
        if type(other)== int :
            return GF2(self.x ^ other)
        elif type(other)== GF2 :
            return GF2(self.x ^ other.x)
        else:
            raise Exception

    def __sub__(self,other):
        # adiditon et soustraction dans GF2(2) sont identiques
        return self.__add__(other)

    def __mul__(self, other):
        assert type(other)== GF2
        # avec a et b dans F2[X]
        res = 0
        self_x = self.x
        other_x = other.x

        while self_x > 0:
            if self_x & 1:
                # l'addition dans GF2(2) c'est un XOR
                # donc on ajoute b
                res = res ^ other_x

            self_x = self_x >> 1
            other_x = other_x << 1

        return GF2(res)

    def _divmod(self, other):
        assert type(other)== GF2


        q, r = 0, self.x
        other_x = other.x

        while GF2._deg(r) >= GF2._deg(other_x):
            d = GF2._deg(r) - GF2._deg(other_x)
            # q = q + x**d
            q = q ^ (1 << d)

            # concretement on fait r = r - other * (x**d)
            r = r ^ (other_x << d)
        return q, r

    def __floordiv__(self, other):
        # on recup le quotient
        return GF2(self._divmod(other)[0])

    def __mod__(self, other):
        # on recup le reste 
        return GF2(self._divmod(other)[1])


class GF2_k():
    def __init__(self,x:int, mod:int):

        assert type(x)==int
        assert type(mod)==int

        self.x = x
        self.mod = mod

        if GF2._deg(x) >= GF2._deg(mod):
            #self.x_reduce = GF2(x)
            # reduction à faire
            self.x = GF2._divmod(GF2(self.x),GF2(self.mod))[1]

    def __str__(self):
        res = f"{str(GF2(self.x))} % {str(GF2(self.mod))} GF(2^{GF2._deg(self.mod)})"
        return res

    def __repr__(self):
        return self.__str__()

    def __eq__(self,other):
        if not isinstance(other,GF2_k):
            return False
        return self.x == other.x and self.mod == other.mod
    
    def is_zero(self):
        return self == GF2_k(0,self.mod)

    def __add__(self,other):
        assert type(other) == GF2_k
        assert self.mod == other.mod

        if type(other) == GF2_k :
            return GF2_k(self.x ^ other.x, self.mod)
        else:
            raise Exception
    
    def __sub__(self,other):
        # addition et soustraction dans GF2(2) sont identiques
        return self.__add__(other)

    def __mul__(self, other):
        assert type(other) == GF2_k
        assert self.mod == other.mod

        p = 0
        self_x = self.x
        other_x = other.x

        while self_x > 0:
            if self_x & 1:
                p = p ^ other_x

            self_x = self_x >> 1
            other_x = other_x << 1

            if GF2._deg(other_x) == GF2._deg(self.mod):
                other_x = other_x ^ self.mod

        return GF2_k(p,self.mod)

    def __floordiv__(self, other):
        assert type(other) == GF2_k
        assert self.mod == other.mod
        # on recup le quotient
        return self * other.inv()

    def inv(self):
        pgcd,x,y = GF2_k.extended_euclidian(GF2(self.x),GF2(self.mod))
        if (pgcd!=GF2(1)):
            raise Exception(f"{self.x} et {self.mod} ne sont pas premier entre eux")
        else:
            return GF2_k(x.x, self.mod)

    def extended_euclidian(a,b):
        assert isinstance(a, GF2)
        assert isinstance(b, GF2)
        #Documentation
        #https://www.youtube.com/watch?v=AA4TBClsjFY

        # Initialisation des poids
        a0,a1=GF2(1),GF2(0) 
        b0,b1=GF2(0),GF2(1)

        # Pour conserver les valeures de a et b
        c,d=a,b
        while (b.x!=0):
            
            q=a//b
            a,b=b,a%b

            c0,c1=b0,b1 # on stocke temporairement b0,b1
            b0,b1=a0-q*b0,a1-q*b1 #on met en jour les coefficients en utilisant le quotient entre a et b
            a0,a1=c0,c1 #on converse uniquement la ligne précédente 

        #print(f"{a}={a0}*{c}+{a1}*{d}")
        return a,a0,a1

    def __pow__(self, k):
        result = GF2_k(1, self.mod)
        poly_to_multiply = self

        while k > 0: # ici on fait LSB first 
            if k & 1: # on test si le LSB est 1
                #si c'est 1 on ajoute
                result = result * poly_to_multiply
            poly_to_multiply = poly_to_multiply * poly_to_multiply   
            k >>= 1 # bit shifting vers la droite

        return result        


class Poly_GF2_k:
    """
    De même, l'anneau des polynômes à coefficients dans un corps commutatif, dispose aussi d'une division euclidienne.

    https://fr.wikipedia.org/wiki/Anneau_euclidien
    """
    def __init__(self,poly:list[GF2_k]):

        if len(poly)>0:
            mod = poly[0].mod
            for coeff in poly:
                if coeff.mod!= mod:
                    raise Exception("All coefficents should have the same modulo")

            self.poly = poly
            self._clean_leading_zero()
        else:
            #polynome avec un seul terme; pas de cleaning
            self.poly = poly
        
    def __call__(self, x:GF2_k):
        assert isinstance(x, GF2_k)
        assert x.mod == self.poly[0].mod

        res = GF2_k(0, self.poly[0].mod)
        deg = self._deg()
        for k in range(len(self.poly)):
            if not self.poly[k].is_zero():
                if deg - k != 0:
                    res += self.poly[k]*x**( deg - k)
                else:
                    res += self.poly[k]
        return res

    def __str__(self):
        res =[]
        deg = self._deg()

        deg_mod = GF2._deg(self.poly[0].mod)

        for index, k in enumerate(self.poly):
            clean_coeff = str(self.poly[index]).split(" % ")[0].rjust(deg_mod*4)
            if index < deg - 1:
                res.append(f"{clean_coeff} * y^{deg - index}")
            elif deg-1 == index:
                res.append(f"{clean_coeff} * y")
            else:
                res.append(f"{clean_coeff}")
        res = " + ".join(reversed(res))

        res = f" % {str(self.poly[0]).split(' % ')[1]}    " + res
        return res

    def __repr__(self):
        return self.__str__()

    def _padding(self_poly, other_poly):

        # padding si pas la meme taille avec des coefficients nuls
        if len(self_poly) > len(other_poly):
            mod_poly_ = other_poly[0].mod
            other_poly = [GF2_k(0,mod_poly_)]*(len(self_poly)-len(other_poly)) + other_poly
        else:
            mod_poly_ = self_poly[0].mod
            self_poly = [GF2_k(0,mod_poly_)]*(len(other_poly)-len(self_poly)) + self_poly
        return self_poly, other_poly

    def is_zero(self):
        return all(c == GF2_k(0, self.poly[0].mod) for c in self.poly)

    def _clean_leading_zero(self):
        zero = GF2_k(0,self.poly[0].mod)

        if not self.is_zero():
            for k in range(len(self.poly)):
                if self.poly[k]!=zero:
                    index = k
                    break
            self.poly = self.poly[index:]
        else:
            self.poly = [zero]

    def _deg(self):
        assert len(self.poly)>=1
        if not self.is_zero():
            return len(self.poly)-1
        else:
            return -1

    def lc(self):
        return self.poly[0]

    def monic(self):
        if not self.is_zero():
            self_poly = self.poly
            res = [coeff//self_poly[0] for coeff in self_poly]
        else:
            res = self.poly[:]
        
        return Poly_GF2_k(res)

    def __eq__(self,other):
        if not isinstance(other, Poly_GF2_k):
            return False

        self_poly = self.poly
        other_poly = other.poly

        res = True

        # meme modulo
        if self_poly[0].mod == other_poly[0].mod and len(self_poly)==len(other_poly):

            for k in range(len(self_poly)):
                if self_poly[k] == other_poly[k]:
                    continue
                else:
                    res = False
                    break
        else:
            res = False

        return res

    def __add__(self,other):
        assert type(other) == Poly_GF2_k

        self_poly = self.poly
        other_poly = other.poly

        # meme modulo
        if self_poly[0].mod == other_poly[0].mod:
            self_poly, other_poly = Poly_GF2_k._padding(self_poly, other_poly)

            res = [a+b for a,b in zip(self_poly, other_poly)]
        else:
            raise Exception
        
        return Poly_GF2_k(res)

    def __sub__(self,other):
        # addition et soustraction dans GF2_k[x] sont identiques
        return self.__add__(other)

    def __mul__(self,other):
        assert type(other) == Poly_GF2_k

        self_poly = self.poly
        other_poly = other.poly 
        
        # meme modulo
        if self_poly[0].mod == other_poly[0].mod:
            if not self.is_zero() and not other.is_zero():
                # on initialise un polynome vide
                res = [GF2_k(0,self_poly[0].mod) for _ in range(self._deg() + other._deg() + 1)]

                for i in range(len(self_poly)):
                    for j in range(len(other_poly)):
                        res[i+j] = res[i+j] + self_poly[i]*other_poly[j]
            else:
                res = [GF2_k(0,self_poly[0].mod)]
        else:
            raise Exception
    
        return Poly_GF2_k(res)

    def __floordiv__(self, other):
        Q, R = self.divmod(other)
        return Q

    def __mod__(self, other):
        Q, R = self.divmod(other)
        return R

    def __pow__(self, k):
        assert type(k)==int

        result = Poly_GF2_k([GF2_k(1, self.poly[0].mod)])
        poly_to_multiply = self

        while k > 0: # ici on fait LSB first 
            if k & 1: # on test si le LSB est 1
                #si c'est 1 on ajoute
                result = result * poly_to_multiply
            poly_to_multiply = poly_to_multiply * poly_to_multiply   
            k >>= 1 # bit shifting vers la droite

        return result  
    
    def pow_mod(self, k, mod):
        isinstance(k, int)
        isinstance(mod, Poly_GF2_k)

        result = Poly_GF2_k([GF2_k(1, self.poly[0].mod)])
        poly_to_multiply = self

        while k > 0: # ici on fait LSB first 
            if k & 1: # on test si le LSB est 1
                #si c'est 1 on ajoute
                result = (result * poly_to_multiply)%mod
            poly_to_multiply = (poly_to_multiply * poly_to_multiply)%mod   
            k >>= 1 # bit shifting vers la droite
        return result

    def divmod(self, other):
        # a verifier 
        assert isinstance(other, Poly_GF2_k)
        assert self.poly[0].mod == other.poly[0].mod

        if other.is_zero():
            raise ZeroDivisionError()
        elif self.is_zero():
            return self, self

        mod = self.poly[0].mod

        if self._deg()>other._deg():
            Q = [GF2_k(0,mod)] * (self._deg() - other._deg() + 1 )
        else:
            Q = [GF2_k(0,mod)]

        R = Poly_GF2_k(self.poly[:])
        
        while R._deg() >= other._deg():

            d = R._deg() - other._deg()
            coeff = R.lc() // other.lc()

            Q[ len(Q) - d -1 ] = coeff

            # On rajoute des zeros pour etre collé au most significant power du polynome
            shifted = [k*coeff for k in (other.poly)] + d*[GF2_k(0,mod)]
            R = R - Poly_GF2_k(shifted)

        return Poly_GF2_k(Q), R

    def extended_euclidian_poly(a,b):
        assert isinstance(a, Poly_GF2_k)
        assert isinstance(b, Poly_GF2_k)
        assert a.poly[0].mod == b.poly[0].mod

        mod = a.poly[0].mod
        #Documentation
        #https://www.youtube.com/watch?v=AA4TBClsjFY

        # Initialisation des poids
        a0,a1=Poly_GF2_k([GF2_k(1,mod)]) , Poly_GF2_k([GF2_k(0,mod)])
        b0,b1=Poly_GF2_k([GF2_k(0,mod)]) , Poly_GF2_k([GF2_k(1,mod)])

        # Pour conserver les valeures de a et b
        c,d=a,b
        while (b!=Poly_GF2_k([GF2_k(0,mod)])):
            
            q=a//b
            a,b=b,a%b

            c0,c1=b0,b1 # on stocke temporairement b0,b1
            b0,b1=a0-q*b0,a1-q*b1 #on met en jour les coefficients en utilisant le quotient entre a et b
            a0,a1=c0,c1 #on converse uniquement la ligne précédente 
            #print(b)

        #print(f"{a}={a0}*{c}+{a1}*{d}")
        return a,a0,a1
    
    def derivative(self):
        # Documentation
        # https://en.wikipedia.org/wiki/Formal_derivative

        mod = self.poly[0].mod

        deg = self._deg()

        derivative = []
        for n in reversed(range(1,deg+1)):
            if n%2==1:
                derivative.append(self.poly[deg-n])
            else:
                derivative.append(GF2_k(0, mod))

        return Poly_GF2_k(derivative)
    
    def _is_square(self):
        return all([self.poly[k].is_zero() for k in range(1,len(self.poly),2)])

    def square_root(self):
        """Calcule la racine carrée d'un polynôme dont tous les exposants sont pairs."""
        assert self._is_square()

        mod_val = self.poly[0].mod
        k = GF2._deg(mod_val) # Degré de l'extension (ex: 4 pour mod=19)
        
        root_coeffs = []
        # On ne prend que les puissances paires (index 0, 2, 4... en partant de la fin)
        # Pour simplifier, on reconstruit le polynôme :
        for i in range(0, len(self.poly), 2):
            c = self.poly[i]
            # Racine carrée du coefficient : c^(2^(k-1))
            # (c^(2^(k-1)))**2 = c^(2*(2**k-1)) = c^(2**k) = c
            root_c = c**(2**(k-1))
            root_coeffs.append(root_c)
        
        res = Poly_GF2_k(root_coeffs)
        assert res * res == self

        return res

    def square_free(f):
        """Retourne les produits de f à la puissance 1."""
        # Warning this a custom non standard square-free 
        # The result aren't exactly the output of Yun algorithm
        # But we don't care in this case

        assert isinstance(f, Poly_GF2_k)
        assert not f.is_zero()

        mod = f.poly[0].mod
               
        factors = []

        while f!=Poly_GF2_k([GF2_k(1, mod)]):
            power = 1
            
            g = f
            while g._is_square():
                g = g.square_root()
                power*=2
            
            g_derivative = g.derivative()
            pgcd, _, _ = Poly_GF2_k.extended_euclidian_poly(g, g_derivative)
            
            factor = g // pgcd
            factors.append([factor.monic(),power])
            f = f // (factor.monic() ** power)

        factors_res = []
        power_res = []
        for k in factors : 
            if k[0] not in factors_res:
                factors_res.append(k[0])
                power_res.append(k[1])
            else:
                power_res[factors_res.index(k[0])] += k[1]

        #sorting par puissance
        return sorted(list(zip(factors_res, power_res)), key=lambda x:x[1])      

    def distinct_degree(f, max_degree=None):
        assert isinstance(f, Poly_GF2_k)

        mod = f.poly[0].mod
        factors = []
        f_ = f
        

        one = GF2_k(1, mod)
        zero = GF2_k(0, mod)
        x = Poly_GF2_k([one, zero])

        degree = GF2._deg(mod)

        i = 1
        while f_._deg()>=2*i:
            print(f"Polynome irreductible 2^{degree}^{i}")
            if i==1:
                x_q_i = x.pow_mod(2**(degree * i), f_)
            else:
                x_q_i = x_q_i.pow_mod(2**degree, f_)

            h = (x_q_i - x) % f_

            pgcd, _, _ = Poly_GF2_k.extended_euclidian_poly(f_, h)

            if pgcd != Poly_GF2_k([one]):
                factors.append((pgcd.monic(), i))
                f_ = (f_ // pgcd).monic()

            if max_degree!=None and i==max_degree:
                break

            i+=1
        
        if f_ != Poly_GF2_k([one]):
            factors.append((f_.monic(), f_._deg()))

        return factors

    def equal_degree_factorization(f, d:int):
        # Cantor-Zassenhaus

        assert isinstance(f, Poly_GF2_k)
        assert isinstance(d, int)

        n = f._deg()
        r = n // d
        mod = f.poly[0].mod
        factors = [f]

        one = GF2_k(1, mod)
        one_poly = Poly_GF2_k([one])
        degree = GF2._deg(mod)

        while len(factors)<r:
            h = Poly_GF2_k.random_polynomial(f)
            g, _, _ = Poly_GF2_k.extended_euclidian_poly(h,f)
            g = g.monic()

            if g == one_poly:
                # statistiquement h ne sera quasiement jamais un produit des facteurs irrédcutibles de f
                # mainteant on va forcer g a être statistiqment un produit des facteurs irréductibles de f
                exposant = (2**(degree*d) - 1)//3 
                g = (h.pow_mod(exposant, f) - one_poly ) %f
                g = g.monic()


            factors_copy = factors[:]
            
            for k in range(len(factors)):
                if factors[k]._deg()!=d:
                    pgcd, _, _ = Poly_GF2_k.extended_euclidian_poly(g, factors[k])
                    pgcd = pgcd.monic()

                    if pgcd!=one_poly and pgcd!=factors[k]:
                        index = factors_copy.index(factors[k]) 
                        factors_copy = factors_copy[:index] + factors_copy[index+1:] + [pgcd, (factors[k]//pgcd).monic()]

            factors = factors_copy

        return factors

    def random_polynomial(f):
        assert isinstance(f, Poly_GF2_k)
        mod = f.poly[0].mod
        deg = f._deg()

        h=[]
        for _ in range(deg):
            h.append(GF2_k(rd.randint(0,mod), mod))
        return Poly_GF2_k(h)




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