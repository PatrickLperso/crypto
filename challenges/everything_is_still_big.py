#!/usr/bin/env python3
import time
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

############################################
# Config
############################################

debug = True
strict = False
helpful_only = True
dimension_min = 7 

############################################
# Functions
############################################

def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1
    print(f"{nothelpful} / {BB.dimensions()[0]} vectors are not helpful")

def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

def remove_unhelpful(BB, monomials, bound, current):
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB

    for ii in range(current, -1, -1):
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            for jj in range(ii + 1, BB.dimensions()[0]):
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj

            if affected_vectors == 0:
                print(f"* removing unhelpful vector {ii}")
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                return remove_unhelpful(BB, monomials, bound, ii-1)

            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print(f"* removing unhelpful vectors {ii} and {affected_vector_index}")
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    return remove_unhelpful(BB, monomials, bound, ii-1)
    return BB

def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    # Setup Polynomial Ring in Sage
    PR = PolynomialRing(ZZ, names=('u', 'x', 'y'))
    u, x, y = PR.gens()
    Q = PR.quotient(x*y + 1 - u) 
    polZ = Q(pol).lift()

    UU = XX*YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x**ii * modulus**(mm - kk) * polZ(u, x, y)**kk
            gg.append(xshift)
    gg.sort()

    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
    
    # y-shifts
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y**jj * polZ(u, x, y)**kk * modulus**(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift)
    
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u**kk * y**jj)

    # Lattice construction
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)

    if helpful_only:
        BB = remove_unhelpful(BB, monomials, modulus**mm, nn-1)
        nn = BB.dimensions()[0]
        if nn == 0:
            return 0,0

    if debug:
        helpful_vectors(BB, modulus**mm)
    
    det = BB.det()
    bound = modulus**(mm*nn)
    if det >= bound:
        print("We do not have det < bound. Try higher m and t.")
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good!)")

    if debug:
        print("Optimizing basis via LLL...")
    BB = BB.LLL()

    found_polynomials = False
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            PR2 = PolynomialRing(ZZ, names=('w', 'z'))
            w, z = PR2.gens()
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)

            rr = pol1.resultant(pol2)
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print(f"Found independent vectors at indices {pol1_idx}, {pol2_idx}")
                found_polynomials = True
                break
        if found_polynomials: break

    if not found_polynomials:
        return 0, 0
    
    PR_q = PolynomialRing(ZZ, names='q')
    q = PR_q.gen()
    rr = rr.univariate_polynomial()
    soly = rr.roots()

    if not soly:
        print("No roots found. delta might be too small.")
        return 0, 0

    y0 = soly[0][0]
    ss = pol1.subs(z=y0).univariate_polynomial()
    solx = ss.roots()[0][0]

    return solx, y0

def example():
    # RSA Constants
    # N = 0xc2fd2913bae61f845ac94e4ee1bb10d8531dda830d31bb221dac5f179a8f883f15046d7aa179aff848db2734b8f88cc73d09f35c445c74ee35b01a96eb7b0a6ad9cb9ccd6c02c3f8c55ecabb55501bb2c318a38cac2db69d510e152756054aaed064ac2a454e46d9b3b755b67b46906fbff8dd9aeca6755909333f5f81bf74db
    # e = 0x19441f679c9609f2484eb9b2658d7138252b847b2ed8ad182be7976ed57a3e441af14897ce041f3e07916445b88181c22f510150584eee4b0f776a5a487a4472a99f2ddc95efdd2b380ab4480533808b8c92e63ace57fb42bac8315fa487d03bec86d854314bc2ec4f99b192bb98710be151599d60f224114f6b33f47e357517

    N = 0xb12746657c720a434861e9a4828b3c89a6b8d4a1bd921054e48d47124dbcc9cfcdcc39261c5e93817c167db818081613f57729e0039875c72a5ae1f0bc5ef7c933880c2ad528adbc9b1430003a491e460917b34c4590977df47772fab1ee0ab251f94065ab3004893fe1b2958008848b0124f22c4e75f60ed3889fb62e5ef4dcc247a3d6e23072641e62566cd96ee8114b227b8f498f9a578fc6f687d07acdbb523b6029c5bbeecd5efaf4c4d35304e5e6b5b95db0e89299529eb953f52ca3247d4cd03a15939e7d638b168fd00a1cb5b0cc5c2cc98175c1ad0b959c2ab2f17f917c0ccee8c3fe589b4cb441e817f75e575fc96a4fe7bfea897f57692b050d2b
    e = 0x9d0637faa46281b533e83cc37e1cf5626bd33f712cc1948622f10ec26f766fb37b9cd6c7a6e4b2c03bce0dd70d5a3a28b6b0c941d8792bc6a870568790ebcd30f40277af59e0fd3141e272c48f8e33592965997c7d93006c27bf3a2b8fb71831dfa939c0ba2c7569dd1b660efc6c8966e674fbe6e051811d92a802c789d895f356ceec9722d5a7b617d21b8aa42dd6a45de721953939a5a81b8dffc9490acd4f60b0c0475883ff7e2ab50b39b2deeedaefefffc52ae2e03f72756d9b4f7b6bd85b1a6764b31312bc375a2298b78b0263d492205d2a5aa7a227abaf41ab4ea8ce0e75728a5177fe90ace36fdc5dba53317bbf90e60a6f2311bb333bf55ba3245f
    c = 0xa3bce6e2e677d7855a1a7819eb1879779d1e1eefa21a1a6e205c8b46fdc020a2487fdd07dbae99274204fadda2ba69af73627bdddcb2c403118f507bca03cb0bad7a8cd03f70defc31fa904d71230aab98a10e155bf207da1b1cac1503f48cab3758024cc6e62afe99767e9e4c151b75f60d8f7989c152fdf4ff4b95ceed9a7065f38c68dee4dd0da503650d3246d463f504b36e1d6fafabb35d2390ecf0419b2bb67c4c647fb38511b34eb494d9289c872203fa70f4084d2fa2367a63a8881b74cc38730ad7584328de6a7d92e4ca18098a15119baee91237cea24975bdfc19bdbce7c1559899a88125935584cd37c8dd31f3f2b4517eefae84e7e588344fa5

    delta = 0.18 
    m = 4 
    t = int((1 - 2*delta) * m)
    # X = 2 * floor(N**delta)
    # Y = floor(N**0.5)

    # Utiliser la fonction native de Python pour la racine carrée entière
    Y = math.isqrt(N)
    
    # Convertir N en un réel Sage de haute précision AVANT la puissance
    RR_prec = RealField(2048)
    
    # On convertit N explicitement, on applique la puissance, puis on re-transforme en entier Python (int)
    X = int(2 * floor(RR_prec(N) ** RR_prec(delta)))

    P = PolynomialRing(ZZ, names=('x', 'y'))
    x, y = P.gens()
    A = (N + 1) // 2
    pol = 1 + x * (A + y)

    if debug:
        print(f"=== Parameters: m={m}, t={t}, delta={delta} ===")
        start_time = time.time()

    solx, soly = boneh_durfee(pol, e, m, t, X, Y)

    if solx > 0:
        d = int(pol(solx, soly) // e)
        print(f"=== SUCCESS: Private key d found: {d} ===")

        flag = long_to_bytes(pow(c, d, N))
        assert flag == b'crypto{bon3h5_4tt4ck_i5_sr0ng3r_th4n_w13n3r5}'
        print(flag)
    else:
        print("=== FAILURE: No solution found ===")

    if debug:
        print(f"=== Execution time: {time.time() - start_time:.2f} seconds ===")

if __name__ == "__main__":
    # implementation de coppermsith mulitvarié par David Wong pour Boneh Durfee
    example()