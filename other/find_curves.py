#!/usr/bin/env sage
"""
Génère des courbes elliptiques E/GF(p) dont l'ordre du groupe est premier,
avec un ordre proche de ~10 000. Utile pour tester Pollard rho / Pohlig-Hellman
sur un sous-groupe d'ordre premier (cas de validité de l'algorithme).

Usage:
    sage find_curves.py
"""

from sage.all import GF, EllipticCurve, is_prime, random_prime


def find_prime_order_curves(target=10000000, how_many=5):
    """
    Cherche `how_many` courbes E/GF(p) d'ordre premier, avec p (donc l'ordre,
    par Hasse) proche de `target`.

    Retourne une liste de tuples (p, a, b, order, Px, Py).
    """
    results = []

    while len(results) < how_many:
        # p premier autour de target (entre target/2 et 2*target)
        p = random_prime(2 * target, lbound=target // 2)
        F = GF(p)

        a = F.random_element()
        b = F.random_element()

        # discriminant non nul → courbe non singulière
        if (4 * a**3 + 27 * b**2) == 0:
            continue

        E = EllipticCurve(F, [a, b])
        order = E.order()

        if is_prime(order):
            # ordre premier → groupe cyclique → tout point != O est générateur
            P = E.gens()[0]
            Px, Py = int(P[0]), int(P[1])
            results.append((int(p), int(a), int(b), int(order), Px, Py))

    return results


def verify(p, a, b, order, Px, Py):
    """Sanity check : la courbe a bien cet ordre premier et P est dessus."""
    F = GF(p)
    E = EllipticCurve(F, [a, b])
    P = E(Px, Py)
    assert E.order() == order
    assert is_prime(order)
    assert (order * P) == E(0)  # P * order = point à l'infini
    return True


if __name__ == "__main__":
    print("Recherche de courbes d'ordre premier autour de 10 000...\n")
    curves = find_prime_order_curves(target=10000000, how_many=1)

    for i, (p, a, b, order, Px, Py) in enumerate(curves, 1):
        verify(p, a, b, order, Px, Py)
        print(f"--- Courbe {i} ---")
        print(f"  p     = {p}")
        print(f"  a     = {a}")
        print(f"  b     = {b}")
        print(f"  order = {order}  (premier)")
        print(f"  P     = ({Px}, {Py})  générateur")
        print()

    # Format prêt à coller dans un test pytest
    print("=" * 60)
    print("Format pytest (à copier dans un parametrize) :\n")
    for (p, a, b, order, Px, Py) in curves:
        print(f"    ({a}, {b}, {p}, {order}, {Px}, {Py}),")