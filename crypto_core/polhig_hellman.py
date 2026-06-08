from crypto_core.elliptic_curve import WeierStrass, PointWeirstrass
from crypto_core.modular_arithmetic import ChineseRemainder, pgcd
import logging
from typing import List, Tuple
from tqdm import tqdm
import random as rd
import psutil, os
import pandas as pd
import hashlib 

# ====== A Lancer en tant que privilégié pour que l'os priorise ce processus ==========
#p = psutil.Process(os.getpid())
#p.nice(-10)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def brute_force(P:PointWeirstrass, Q:PointWeirstrass, number_possibilities:int):
    # ==== Computing a of Q=aP by bruteforcing ===========
    for k in tqdm(range(1,number_possibilities+1)):
        if Q==k*P:
            return k
    raise Exception("not found")

def random_function(X_i:PointWeirstrass, a:int, b:int, P:PointWeirstrass, Q:PointWeirstrass, order:int):
    if not X_i.infinity:
        X_i_mod_3 = X_i.x%3
    else: 
         X_i_mod_3=1

    if X_i_mod_3==0:
        return  2*X_i, (2*a)%order,(2*b)%order
    elif X_i_mod_3==1:
        return  X_i+P, (a+1)%order, b%order
    else:
        return  X_i+Q, a%order, (b+1)%order


def progress_filename(P: PointWeirstrass, Q: PointWeirstrass, order: int) -> str:
    """
    construit un nom unique de fichier selon P, Q, le sous groupe
    """
    key = f"{P.curve.a}:{P.curve.b}:{P.curve.p}:{P.x}:{P.y}:{Q.x}:{Q.y}:{order}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    return f"{order}_{digest}.csv"

def save_progress_file(k:int, P:PointWeirstrass, order:int, Q:PointWeirstrass, X_i:PointWeirstrass, A_i:int, B_i:int, x_i:PointWeirstrass, a_i:int, b_i:int, folder:str, csv_path:str):

    if not os.path.exists(folder):
        os.mkdir(folder)

    file_exist = os.path.exists(csv_path)

    df = pd.DataFrame([{
                        "k": k,
                        "curve_a": P.curve.a,
                        "curve_b": P.curve.b,
                        "curve_p": P.curve.p,
                        "order": order,
                        "P.x": P.x,
                        "P.y": P.y,
                        "Q.x": Q.x,
                        "Q.y": Q.y,
                        "X_i.x": X_i.x,
                        "X_i.y": X_i.y,
                        "A_i": A_i,
                        "B_i": B_i,
                        "x_i.x": x_i.x,
                        "x_i.y": x_i.y,
                        "a_i": a_i,
                        "b_i": b_i
    }])

    if file_exist:
        last_row = pd.read_csv(csv_path).tail(1).iloc[0]
        last_iteration_saved = int(last_row["k"])
        if k>last_iteration_saved:
            df.to_csv(
                csv_path,
                mode="a",
                header=False,
                index=False
            )
    else:
        df.to_csv(
            csv_path,
            mode="a",
            header=True,
            index=False
        )


def pollard_rho(P:PointWeirstrass, Q:PointWeirstrass, order:int, init:int, reprise_file:bool, save_progress:bool, max_iterations=90000000):
    

    # on recherche une collision X_i == x_i 
    # avec X_i = A_i*P+B_i*Q et x_i =a_i*P+b_i*Q
    # si on peut inverser b_i-B_i, on a = (A_i-a_i)*inv(b_i-B_i)
    # complexité n**0.5 probabiliste, grâce aux collisions

    # Pour mettre de l'aléatoire au point de départ
    # coeff_random = rd.randint(1,min(order,10**6))%order

    # X_i = coeff_random*P
    # x_i = coeff_random*P
    # A_i, B_i = coeff_random, 0
    # a_i, b_i = coeff_random, 0
    folder = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "progress")

    csv_path = os.path.join(folder, progress_filename(P, Q, order))
    file_exist = os.path.exists(csv_path)

    if not reprise_file or not file_exist:
        A_i, B_i = init, 0
        a_i, b_i = 1, 0

        X_i = A_i*P + B_i*Q
        x_i = a_i*P + b_i*Q

        start=0
    else:
        last_row = pd.read_csv(csv_path).tail(1).iloc[0]

        curve=WeierStrass(int(last_row["curve_a"]), int(last_row["curve_b"]), int(last_row["curve_p"]))
        assert P==PointWeirstrass(curve, int(last_row["P.x"]),int(last_row["P.y"]))
        assert Q==PointWeirstrass(curve, int(last_row["Q.x"]),int(last_row["Q.y"]))

        X_i = PointWeirstrass(curve, int(last_row["X_i.x"]),int(last_row["X_i.y"]))
        x_i = PointWeirstrass(curve, int(last_row["x_i.x"]),int(last_row["x_i.y"]))
        A_i, B_i = int(last_row["A_i"]),  int(last_row["B_i"])
        a_i, b_i = int(last_row["a_i"]),  int(last_row["b_i"])

        start=int(last_row["k"])

        logging.info(f"Reprise à l'étape: {start}, fichier de cassage chargé : {csv_path}")



    a=None
    max_iterations= min(max_iterations,order)
    SAVE_INTERVAL = 10**5


    for k in tqdm(range(start, max_iterations), initial=start, total=max_iterations):
        if k%SAVE_INTERVAL==0 and k!=0 and save_progress:
            save_progress_file(k, P, order, Q, X_i, A_i, B_i, x_i, a_i, b_i, folder, csv_path)

        X_i, A_i, B_i = random_function(X_i,A_i,B_i, P, Q, order)

        x_i, a_i, b_i = random_function(x_i,a_i,b_i, P, Q, order)
        x_i, a_i, b_i = random_function(x_i,a_i,b_i, P, Q, order)
        
        # Cycle Detection Floyd 
        # https://fr.wikipedia.org/wiki/Algorithme_du_li%C3%A8vre_et_de_la_tortue
        if X_i==x_i:
            if pgcd(b_i-B_i, order) != 1:
                a=None
            else:
                a=(A_i-a_i)*pow(b_i-B_i,-1,order)%order
            break
    logging.info(f"nombre iterations : {k}, order : {order}")
    return a

def polhig_hellman(P:PointWeirstrass, Q:PointWeirstrass, order:int, order_prime_decomposition:List[tuple[int,int]], fast:bool = False,list_prime_avoid:list[int]=[]):
    # =========================== Computing a of Q=aP of a weak curve ==========================
    # ===== Based on https://www.hyperelliptic.org/tanja/teaching/crypto22/20220927-ph.pdf =====
    # ==================== And https://risencrypto.github.io/PohligHellman/ ====================

    if P.curve != Q.curve:
        raise Exception("Point not on the same curve")
    
    n=1
    decompo=[]
    for prime, power in order_prime_decomposition:
        n*=prime**power
        decompo.append(f"{prime}^{power}")

    if order!=n:
        raise Exception("The Order and Decomposition doesn't match")
    logging.info(f"The order of the curve is supposed to be {n}={'*'.join(decompo)}")

    a_i_list=[]

    for p_i, power in order_prime_decomposition:
        if p_i not in list_prime_avoid :
            logging.info(f"Running Pohlig on modulo {p_i}^{power}")
            Q_i = Q
            n_i = n // p_i
            R_i = n_i * P

            a_i_j = 0
            a_i = 0

            for j in range(0,power):
                if j>0:
                    n_i //= p_i
                    Q_i = Q_i - a_i_j * (p_i**(j-1))*P
                S_i = n_i * Q_i

                # on cherche a_i_j tel que S_i=a_i_j*R_i
                #a_i_j = brute_force(R_i, S_i, p_i) 
                if p_i < 100 :
                    a_i_j = brute_force(R_i, S_i, p_i) 
                else:
                    if p_i>10**11:
                        save_progress=True
                        reprise_file=True
                    else:
                        save_progress=False
                        reprise_file=False

                    k = 0
                    a_i_j = pollard_rho(R_i, S_i, p_i, init = k, reprise_file=reprise_file, save_progress=save_progress)
                    while a_i_j is None: # si a_i_j est tombée sur une collision non inversible
                        k+=1
                        print(f"collision non inversible : n°{k}")
                        a_i_j = pollard_rho(R_i, S_i, p_i, init = k,  reprise_file=reprise_file, save_progress=save_progress)
                a_i +=a_i_j*p_i**j

            a_i_list.append(a_i)
    
    crt_system_equations = list(zip(a_i_list,list(map(lambda x:x[0]**x[1],order_prime_decomposition))))
    if list_prime_avoid:
        return crt_system_equations
    return ChineseRemainder(crt_system_equations, fast)


if __name__ == "__main__":

    # # ========== En cas de longue tâche ==========
    # # sudo nohup ../venv_crypto/bin/python3 polhig_hellman.py > log_moving_problems.txt 2>&1 &

    curve1=WeierStrass(1001, 75, 7919)
    order_curve=7889
    
    # #======== Test BruteForce ==========
    print("===== BruteForce ====")
    P=PointWeirstrass(curve1, 4023,6036)
    Z=2000*P
    assert 2000==brute_force(P,Z,order_curve)
    del P

    # #========= Test Pollard ============
    print("===== pollard rho ====")
    P=PointWeirstrass(curve1, 4023,6036)
    Q=2000*P
    solution = pollard_rho(P, Q, order=7889, init = 0, reprise_file=False, save_progress=False, max_iterations=7889)
    while solution is None:
        k+=1
        print(f"collision non inversible : n°{k}")
        solution = pollard_rho(P, Q, order=7889, init = k, reprise_file=False, save_progress=False,  max_iterations=7889)
    assert Q==solution * P
    del P, Q

    # # ======== Test Polhig Hellmann =======

    P=PointWeirstrass(curve1, 4023,6036)
    Q=PointWeirstrass(curve1, 4135,3169)

    order=7889
    order_prime_decomposition=[(7,3),(23,1)]

    solution,modulo=polhig_hellman(P, Q, order, order_prime_decomposition, fast=False)
    assert solution,modulo == (4334,7889)
    assert solution*P == Q
    assert (10*modulo+solution)*P == Q
    


