


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

