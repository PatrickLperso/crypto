

if __name__ == "__main__":
    # ====================== Gram Schmidt ====================
    # Définir les vecteurs comme des listes ou tuples

    v1 = [4, 1, 3, -1]
    v2 = [2, 1, -3, 4]
    v3 = [1, 0, -2, 7]
    v4 = [6, 2, 9, -5]

    # Créer la matrice en empilant les vecteurs (par ligne)
    basis = np.array([v1, v2, v3, v4], dtype=np.float128)

    gram_shmidt = gram_schmidt(basis)

    # ====================== Gaussian reduction ====================

    basis = np.array([[ 846835985, 9834798552],
                      [  87502093,  123094980]])
    
    assert np.all(np.array([[   87502093,   123094980],
                     [-4053281223,  2941479672]]) == gaussian_lattice_reduction(basis))


    # ====================== Find the lattice ====================

    q = 7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257
    h = 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800

    # on construit une lattice tel que [g,f](vecteur court est contenu dedans)
    # g et f sont tous les deux inférieurs à sqrt(q//2)
    # attention vecteur sous forme de ligne basis*X = [g,f]

    basis = np.array([[q, 0], [h, 1]], dtype=object)
    test = gaussian_lattice_reduction(basis)

    g = test[0,0]
    f = test[0,1]

    assert f == (pow(h, -1, q)*g)%q

    cipher = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523
    flag = long_to_bytes(decrypt(q, h, f, g, cipher))
    assert flag == b'crypto{Gauss_lattice_attack!}'
    
