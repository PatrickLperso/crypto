import math
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, inverse
from gmpy2 import is_prime
from functools import reduce

import os, sys

from cryptography.hazmat.primitives import serialization

FLAG = b"crypto{????????????}"

primes = []


# def sieve(maximum=10000):
#     # In general Sieve of Sundaram, produces primes smaller
#     # than (2*x + 2) for a number given number x. Since
#     # we want primes smaller than maximum, we reduce maximum to half
#     # This array is used to separate numbers of the form
#     # i+j+2ij from others where 1 <= i <= j
#     marked = [False]*(int(maximum/2)+1)

#     # Main logic of Sundaram. Mark all numbers which
#     # do not generate prime number by doing 2*i+1
#     for i in range(1, int((math.sqrt(maximum)-1)/2)+1):
#         for j in range(((i*(i+1)) << 1), (int(maximum/2)+1), (2*i+1)):
#             marked[j] = True

#     # Since 2 is a prime number
#     primes.append(2)

#     # Print other primes. Remaining primes are of the
#     # form 2*i + 1 such that marked[i] is false.
#     for i in range(1, int(maximum/2)):
#         if (marked[i] == False):
#             primes.append(2*i + 1)


# def get_primorial(n):
#     result = 1
#     for i in range(n):
#         result = result * primes[i]
#     return result


# def get_fast_prime():
#     M = get_primorial(40)
#     while True:
#         k = random.randint(2**28, 2**29-1)
#         a = random.randint(2**20, 2**62-1)
#         p = k * M + pow(e, a, M)

#         if is_prime(p):
#             return k, a, p


# sieve()

# e = 0x10001
# m = bytes_to_long(FLAG)

# k1, a1, p = get_fast_prime()
# k2, a2, q = get_fast_prime()

# n = p * q
# phi = (p - 1) * (q - 1)
# d = inverse(e, phi)


# def break_k1_k2(n, k1, a1, p, k2, a2, q, e):
#     M = get_primorial(40)


#     # k2_e_a1_k1_e_a2 = ((n - e_a1_a2)//M)%M
    
#     # k1_k2 = (n - e_a1_a2 - M*k2_e_a1_k1_e_a2) // M**2
#     crt_system_equations = []
#     orders = {}

#     for prime in primes[:40]:
#         if prime !=2:
#             if prime == 97:
#                 print("toto")
#             # pour éviter un bug de merde
#             list_prime_avoid = []

#             print(f" ==================== prime : {prime} ================")
#             e_a1_a2_mod_prime = (n%prime)          

#             # =========== on calcule les sous groupes interressants =========
#             # ========= a savoir qui n'ont pas ete préalablement effectues ou qui rapportent de l'info ================

#             # attention c'est les sous gruoupes de e, qui n'est pas un générateur
#             order_prime_decomposition = list(Integer(prime-1).factor())
#             order_g = order_g_f(e, prime, order_prime_decomposition)

#             for k in order_g[0]:

#                 if k[0] in orders.keys() and k[1]<=orders[k[0]]:
#                     list_prime_avoid.append(int(k[0]))
#                 else:
#                     orders[int(k[0])] = int(k[1])

#             # pour eviter un bug stupide ed formattage
#             if len(list_prime_avoid)==0:
#                 list_prime_avoid.append(-1)

#             # ================ on run pohlig hellmann pour le DLP ==================
#             pohlig = polhig_hellman(e_a1_a2_mod_prime, e, prime, order_prime_decomposition=order_prime_decomposition, list_prime_avoid=list_prime_avoid)
#             if len(pohlig)!=0:
#                 crt_system_equations.append(pohlig)
    
#     # ======== on enleve les sous groupes remplacés par des sous groupesplus efficaces =======
#     # =====================             du style 2**2  par 2**3                  =============
#     # =================         on aurait pu le faire avant mais bon bref        =============  
#     remove_low_subgroup = []
#     for crt in reversed(list(map(lambda x:x[0],crt_system_equations))):
#         append = True
#         for ctr_remove_low_subgroup in remove_low_subgroup:
#             if ctr_remove_low_subgroup[1]%crt[1]==0:
#                 append = False
#                 break
#         if append:
#             remove_low_subgroup.append(crt)

#     # il faut s'assurer que les ordersoit premiers entre eux attention
#     a1_a2 = ChineseRemainder(remove_low_subgroup, order_g)
#     return a1_a2

# break_k1_k2(n, k1, a1, p, k2, a2, q, e)

# key = RSA.construct((n, e, d))
# cipher = PKCS1_OAEP.new(key)
# ciphertext = cipher.encrypt(FLAG)

# assert cipher.decrypt(ciphertext) == FLAG

# exported = key.publickey().export_key()
# with open("key.pem", 'wb') as f:
#     f.write(exported)

# with open('ciphertext.txt', 'w') as f:
#     f.write(ciphertext.hex())


# j'ai du mal à comprendre ce challenge
# si on extrait le module il est petit par construction et donc les p et q sont dans factordb



if __name__ == "__main__":
    # c'est la ROCA vulnérabilité
    # a creuser plus en details pour etre capable de la reproduire 
    # https://www.youtube.com/watch?v=lg7FAO730Q8
    # https://bitsdeep.com/posts/analysis-of-the-roca-vulnerability/

    # Papier originel :
    # https://crocs.fi.muni.cz/_media/public/papers/nemec_roca_ccs17_preprint.pdf

    # mais en gros on se base surout sur un M' tel qu'il soit suffisament grand pour que M' > N/4 et ainsi
    # que Coppersmith fonctionne mais il faut aussi qu'il soit sufffisameen tpetit 
    # tel que ord(M') nous permette de bruteforcer toues les possibiltés de l'équation
    # p = k * M' + 65537**(a') mod M'
    # on va itérer sur tous les a' ou presque et résoudre un LLL coppermsith 
    # avec f(x) = x * M' + 65537**(a') mod M' mod N
    # si la racine x trouve (qui est notre k)
    # nous donne un p_test = k * M' + 65537**(a') mod M'
    # tel que p_test divise n alors on a trouvé la factorisation
    # donc ce qui est fait et de tester tous les a possibles 
    # on ne peut pas prednre M directement car ord(65536, M) est trop grand pour du bruteforce
    # on atteint un trade off entre un grand M' où coppersmith est rapide mais le bruteforce sur a' est lent
    # et à l'inverse peu de a' mais M' petit donc coppersmith lent

    # .3.3 Main idea. A crucial observation for further optimization
    # is that the bit size of M is analogous to the number of known bits
    # in Coppersmith’s algorithm. It is sufficient to have just log2 (N )/4
    # bits of p for Coppersmith’s algorithm [22]. In our case, the size of
    # M is much larger than required (log2 (M ) > log2 (N )/4). The main
    # idea is to find a smaller M ′ with a smaller corresponding number
    # of aempts ordM′ (65537) such that the primes are still of the form
    # (1), with M replaced by M ′ and a, k replaced by a′, k ′. The form
    # of the primes p, q implies that the modulus N is of the form (2)
    # and (3) also for M ′ – of course with new corresponding variables
    # a′, b′, c ′, k ′, l ′.
    # In order to optimize the na¨ıve method, we are looking for M ′
    # such that:
    # (1) primes (p, q) are still of the form (1) – M ′ must be a divisor
    # of M;
    # (2) Coppersmith’s algorithm will find k ′ for correct guess of
    # a′ – enough bits must be known (log2 (M ′) > log2 (N )/4);
    # (3) overall time of the factorization will be minimal – number
    # of aempts (ordM′ (65537)) and time per aempt (running
    # time of Coppersmith’s algorithm) should result in a mini-
    # mal time.
    # For practical factorization, there is a trade-off between the num-
    # ber of aempts and the computational time per aempt as Cop-
    # persmith’s algorithm runs faster when more bits are known (see
    # Figure 2). In fact, we are looking for an optimal combination of
    # value M ′ and parameters (m, t – for more details, see Section 2.7)
    # of Coppersmith’s algorithm. It should be noted that the search for
    # value of M ′ is needed only once for each key size. The optimal pa-
    # rameters M ′, m, t along with N serve as inputs to our factorization
    # Algorithm 1

    # l'algo :

    # Input : N , M ′, m, t
    # Output : p  factor of N
    # c ′ ← log_65537(N) mod M ′ . Use Pohlig–Hellman alg;
    # ord ′ ← ordM′ (65537) . See Section 2.6 for method;
    # for all a′ ∈ [ c′/2 , (c′+ord′)/2] do
    #   f (x ) ← x + (M ′−1 mod N ) ∗ (65537**a′ mod M ′) (mod N );
    #   (β, X ) ← (0.5, 2 ∗ N β /M ′) . Seeting parameters;
    #   k ′ ← Coppersmith( f (x ), N , β, m, t, X );
    #   p ← k ′ ∗ M ′ + (65537**a′ mod M ′) . Candidate for a factor;
    #   if N mod p = 0 then
    #       return p
    #   end
    # end

    # Algorithm 1: The factorization algorithm for RSA public keys N
    # generated by the RSALib. The input of the algorithm is a modu-
    # lus N of the form (1) with M ′ as a product of small primes and
    # optimized parameters m, t for Coppersmith’s method

    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    key_path = os.path.join(folder, "key_fast_primes.pem")

    public_key = serialization.load_pem_public_key(open(key_path, "rb").read())
    n = public_key.public_numbers().n
    ciphertext_OEAP = bytes.fromhex("249d72cd1d287b1a15a3881f2bff5788bc4bf62c789f2df44d88aae805b54c9a94b8944c0ba798f70062b66160fee312b98879f1dd5d17b33095feb3c5830d28")

    p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
    q = 77342270837753916396402614215980760127245056504361515489809293852222206596161

    assert p*q == n

    phi = (p - 1) * (q - 1)
    e = 0x10001
    d = inverse(e, phi)

    key = RSA.construct((n, e, d))
    cipher = PKCS1_OAEP.new(key)
    flag = cipher.decrypt(ciphertext_OEAP)
    assert flag == b'crypto{p00R_3570n14}'




