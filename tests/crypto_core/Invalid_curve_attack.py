

if __name__ == "__main__":
    # NIST P-256

    # ================== Courbe et paramètre et initalisation du challenge ===============
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    order = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    curve = WeierStrass(a,b,p)
    G = PointWeirstrass(curve, 48439561293906451759052585252797914202762949526041747995844080717082404635286,36134250956749795798585127919587881956611106672985015071877198253568414405109)
    challenge = Challenge(curve, G)

    logging.info(f"private_key: {challenge.server.secret}")

    # ================== Génération des courbes vulnérables ===============
    logging.info(f"\n=============Curves generation ================")
    # on une limite min pour ne pas avoir à bruteforce un système CRT trop complexe à la fin (on aura toujours k ou -k possible)
    # donc éliminer les nombres premiers trop petits permet de s'assurer que le brutefroce du CRT à la fin ne sera pas trop gourmand 
    # si 15 nombre premiers 2**15 systmes du CRT possibles si 20 2**20 etc ..
    primes_curves, b_primes=generate_invalid_curves(a,p,order,min_order_bruteforce=5000, max_order_bruteforce=5000000, bmax=50)
    
    # ================== Bruteforce des sous groupes et attaque sur ECDH ===============
    logging.info(f"\n============= ECDH exchanges and AES bruteforce==============")

    message_uncipher = b"SERVER_TEST_MESSAGE"
    crt_system_equations = bruteforce_aes(b_primes, primes_curves, message_uncipher, interface=challenge.challenge)

    # ================== Bruteforce des signes du système d'équations ===============
    logging.info(f"\n=========== Bruteforce CRT equations system signs ======")
    solution = bruteforce_sign_crt(crt_system_equations, G, message_uncipher, order, interface=challenge.challenge)
    logging.info(f"solution:{solution}")

    # ================== Récupération du flag ===============
    cipher = bytes.fromhex(challenge.before_input.split("\n")[4].split(" : ")[1])
    iv = cipher[:16]
    message_cipher = cipher[16:]
    
    flag = unpad(key_uncipher(solution, challenge.client_public_key, iv, message_cipher),16)
    assert flag == FLAG

