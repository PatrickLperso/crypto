from crypto_core.modular_arithmetic import ChineseRemainder, pgcd
import logging
from typing import List, Tuple
from tqdm import tqdm
import random as rd
import psutil, os
import pandas as pd
import random
from crypto_core.modular_arithmetic import extended_euclidian
from sage.all import Integer
from functools import reduce

# ====== A Lancer en tant que privilégié pour que l'os priorise ce processus ==========
#p = psutil.Process(os.getpid())
#p.nice(-10)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def brute_force(h:int, g:int, order:int, p:int):
    # ==== Computing x of h=g^x mod p by bruteforcing ===========
    for k in tqdm(range(0,order+1)):
        if h==pow(g, k, p):
            return k
    raise Exception("not found")

def random_function(X_i:int, a:int, b:int, h:int, g:int, order:int, p:int):

    if X_i%3==0: 
        return  (X_i*X_i)%p, (2*a)%(order),(2*b)%(order)
    elif X_i%3==1:
        return  (X_i*g)%p, (a+1)%(order), b%(order)
    else:
        return  (X_i*h)%p, a%(order), (b+1)%(order)

def pollard_rho(h:int, g:int, order:int, p:int, init=0,max_iterations=90000000):
    # ==== Computing a of h=g^a mod p by bruteforcing ===========

    A_i, B_i = init, 0
    a_i, b_i = 0, 0

    X_i = pow(g, A_i,p)*pow(h, B_i,p)
    x_i = pow(g, a_i,p)*pow(h, b_i,p)

    start=1
    max_iterations= min(max_iterations,order+1)
    SAVE_INTERVAL = 10**5

    a=None
    for k in tqdm(range(0, max_iterations)):
        X_i, A_i, B_i = random_function(X_i,A_i,B_i, h, g, order, p)

        x_i, a_i, b_i = random_function(x_i,a_i,b_i, h, g, order, p)
        x_i, a_i, b_i = random_function(x_i,a_i,b_i, h, g, order, p)

        assert X_i==(pow(g, A_i,p)*pow(h, B_i,p))%p
        assert x_i==(pow(g, a_i,p)*pow(h, b_i,p))%p
        
        # Cycle Detection Floyd 
        # https://fr.wikipedia.org/wiki/Algorithme_du_li%C3%A8vre_et_de_la_tortue
        
        if X_i==x_i:
            #print(X_i, x_i)
            d = pgcd(b_i-B_i, order)
            if d != 1:
                pass
            else:
                a=((A_i-a_i)*pow(b_i-B_i,-1,order))%order
            break
    logging.info(f"nombre iterations : {k}, order : {order}")
    return a

def order_g_f(g, p, order_prime_decomposition):

    order_g_prime_decomposition = []
    order_g_power_decomposition  = []
    order_g = 1

    for prime_power in order_prime_decomposition:
        order_g_power_inter=0

        for power in reversed(range(1,prime_power[1]+1)):
            if pow(g, (p-1)//(prime_power[0]**power), p) == 1:
                break
            else:
                order_g_power_inter += 1

        if order_g_power_inter>=1:
            order_g *= prime_power[0]**order_g_power_inter
            order_g_prime_decomposition.append(prime_power[0])
            order_g_power_decomposition.append(order_g_power_inter)
    return list(zip(order_g_prime_decomposition, order_g_power_decomposition)), order_g


def polhig_hellman(h:int, g:int, p:int, fast:bool = False,order_prime_decomposition:list[list[int,int]]=[], order_prime_decomposition_g:list[list[int,int]]=[], list_prime_avoid:list[int]=[]):
    # =========================== Computing a of h=g^x mod p of a weak DLP ==========================
    # attention au cas où g n'est pas un générateur
    # https://risencrypto.github.io/PohligHellman/

    if Integer(p).is_prime():
        if len(order_prime_decomposition) ==0:
            order_prime_decomposition = list(Integer(p-1).factor())

        # attention ca va buguer mainteant ca si on veut dégager des puissances top grandes 
        # order_prime_decomposition = [(int(k[0]),int(k[1])) for k in order_prime_decomposition if k[0] not in list_prime_avoid]

        # Pour traiter le cas où g n'est pas un générateur de toute la courbe 
        if len(order_prime_decomposition_g)==0:
            order_prime_decomposition, order_g = order_g_f(g, p, order_prime_decomposition)
        else:
            order_prime_decomposition = order_prime_decomposition_g
            order_g = reduce(lambda x, y: x * y, [k[0]**k[1] for k in order_prime_decomposition_g]) 
            
    else:
        raise Exception("p is not prime")

    # ordre du DLP
    n = order_g

    a_i_list=[]

    for p_i, power in order_prime_decomposition:
        if p_i not in list_prime_avoid :
            logging.info(f"Running Pohlig on modulo {p_i}^{power}")
            h_i = h
            n_i = n // p_i
            r_i = pow(g, n_i, p)

            a_i_j = 0
            a_i = 0

            for j in range(0,power):
                if j>0:
                    n_i //= p_i
                    h_i = h_i * pow(g, -a_i_j * (p_i**(j-1)), p) %p
                s_i = pow(h_i, n_i, p) 

                # on cherche a_i_j tel que s_i=r_i^a_i_j
                
                if p_i < 100 :
                    a_i_j = brute_force(s_i, r_i, p_i-1 , p) 
                else:
                    if p_i>10**11:
                        save_progress=True
                        reprise_file=True
                    else:
                        save_progress=False
                        reprise_file=False

                    
                    k=0
                    a_i_j = pollard_rho(s_i, r_i, p_i , p, init=0) 
                    while a_i_j is None: # si a_i_j est tombée sur une collision non inversible
                        k+=1
                        print(f"collision non inversible : n°{k}")
                        a_i_j = pollard_rho(s_i, r_i, p_i , p, init=k) 


                a_i +=a_i_j*p_i**j

            a_i_list.append(a_i)
    
    crt_system_equations = list(zip(a_i_list,list(map(lambda x:x[0]**x[1],[p_i for p_i in order_prime_decomposition if p_i[0] not in list_prime_avoid]))))
    if list_prime_avoid:
        return crt_system_equations
    return ChineseRemainder(crt_system_equations, fast)


if __name__ == "__main__":

    # # ========== En cas de longue tâche ==========
    # # sudo nohup ../venv_crypto/bin/python3 polhig_hellman.py > log_moving_problems.txt 2>&1 &

    # ============= test ============
    g=2
    p=268435459
    key = 18184746073
    h = pow(g, key, p)
    solution = polhig_hellman(h, g, p, True)
    assert solution[0]%(p-1) == key%(p-1)
    print(solution)

