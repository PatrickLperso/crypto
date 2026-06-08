

if __name__ == "__main__":
    curve1=WeierStrass(497, 1768, 9739)
    G=PointWeirstrass(curve1,1804,5368)

    # ========== Point Inverse & Infinity ===========
    
    P=PointWeirstrass(curve1, 8045,6936)
    Q=-P
    Z=P+Q
    assert Q==PointWeirstrass(curve1, 8045,2803)
    assert Z==PointWeirstrass(curve1) # point at infinity
    assert P-P==PointWeirstrass(curve1) # point substraction
    del P, Q, Z

    # =========== Point Addition ===========
    
    X=PointWeirstrass(curve1, 5274,2841)
    Y=PointWeirstrass(curve1, 8669,740)

    assert X+Y==PointWeirstrass(curve1, 1024,4440)
    assert X+X==PointWeirstrass(curve1, 7284,2107)

    P=PointWeirstrass(curve1, 493,5564)
    Q=PointWeirstrass(curve1, 1539,4742)
    R=PointWeirstrass(curve1, 4403,5202)

    S=P+P+Q+R
    assert S==PointWeirstrass(curve1, 4215,2162)
    del X,Y,P,Q,R,S

    # ========== Scalar Multiplication ===========
    
    X=PointWeirstrass(curve1, 5323,5438)
    assert 1337*X==PointWeirstrass(curve1,1089,6931)

    P=PointWeirstrass(curve1, 2339,2213)
    Q=7863*P
    assert Q==PointWeirstrass(curve1,9467,2742)
    del X,P,Q

    
    # =========== Shared Secret from Public Point ============
    
    #Alice Public Key
    AliceKey=PointWeirstrass(curve1, 815,3190)
    secret=1829 #secret key
    shared_secret_sha1=ECDH.shared_secret_sha1(secret, AliceKey)
    assert shared_secret_sha1=="80e5212754a824d3a4aed185ace4f9cac0f908bf"
    del AliceKey, secret, shared_secret_sha1

    # =========== Shared Secret from Public x Coordinate ===============
    
    x=4726
    secret=6534
    AliceKey=curve1.point_from_x(x)

    shared_point=ECDH.share_point_from_point(secret, AliceKey)
    iv = "cd9da9f1c60925922377ea952afc212c"
    ciphertext = "febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8"

    assert ECDH.decrypt_flag(shared_point.x, iv, ciphertext)=='crypto{3ff1c1ent_k3y_3xch4ng3}'
    del x, secret, AliceKey, shared_point, iv, ciphertext

    # =========== Shared Secret from Public x Coordinate ===============
    curve2=Montgomery(1, 486662, (2**255)-19)
    x=9
    G=curve2.point_from_x(x)
    Q=21130179955454*G

    assert Q.x==49231350462786016064336756977412654793383964726771892982507420921563002378152
    del x, G, Q