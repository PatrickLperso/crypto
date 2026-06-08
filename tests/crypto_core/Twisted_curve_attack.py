
if __name__ == "__main__":
    
    t1=time()

    # ========== Curve parameter ==========
    p = 2**192 - 237
    a = -3
    b = 1379137549983732744405137513333094987949371790433997718123
    order = 6277101735386680763835789423072729104060819681027498877478
    limit_prime_pohlig = 10**13

    # ========== Private key ==========
    scalar = int.from_bytes(os.urandom(24), "big")
    scalar = min(scalar % order, (order - scalar) % order)

    print(f" private key : {scalar}")

    # scalar = 2948306227418300673296973821543438842352265484304963330490  # solution 1
    # scalar = 1191366691553679168291613729018049848093918470094984820357  # solution 2
    # scalar = 2522942703444388320672704179922209746951556402929845453750  # solution 3
    # scalar = 480741244806338836306541178899819119025113411194700564656   # solution 4 

    # ========== Polhig Hellamn on Curve and Twist on breakable power ==========

    interface = scalarmult

    G_weirstrass, x_scalar_weirstrass, crt_system_equations1=break_curve(a,b,p,interface,scalar,limit_prime_pohlig)
    G_twist_weirstrass, x_scalar_twist, crt_system_equations2=break_twist(a,b,p,interface,scalar,limit_prime_pohlig)  

    # ========== Avant polhig Hellman on fait un choix car quand on nous renvoie l coordonée x on peut choisir P(x, +/y) avec tonneli
    # ==========   on doit donc rendre coherent le système d'équation pour CRT ==========  

    # on s'assure de pas avoir de sous groupe en doublons pour le CRT 
    solution = crt_system_equation_solution(crt_system_equations1, crt_system_equations2, order, G_weirstrass, x_scalar_weirstrass)
    
    assert scalar==solution
    

