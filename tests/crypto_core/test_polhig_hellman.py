


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
    


