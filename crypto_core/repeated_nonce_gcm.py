from Crypto.Cipher import AES
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes

from crypto_core.galois_field import GF2_k, Poly_GF2_k

IV = os.urandom(12)
KEY = os.urandom(16)
FLAG = "crypto{blabla}"

def decrypt(nonce, ciphertext, tag, associated_data):
    ciphertext = bytes.fromhex(ciphertext)
    tag = bytes.fromhex(tag)
    header = bytes.fromhex(associated_data)
    nonce = bytes.fromhex(nonce)

    if header != b'CryptoHack':
        return {"error": "Don't understand this message type"}

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    encrypted = cipher.update(header)
    try:
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        return {"error": "Invalid authentication tag"}

    if b'give me the flag' in decrypted:
        return {"plaintext": FLAG.encode().hex()}

    return {"plaintext": decrypted.hex()}

def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    header = b"CryptoHack"

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=IV)
    encrypted = cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    if b'flag' in plaintext:
        return {
            "error": "Invalid plaintext, not authenticating",
            "ciphertext": ciphertext.hex(),
        }

    return {
        "nonce": IV.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
        "associated_data": header.hex(),
    }

def xor(a, b):
    # ok 
    return b''.join([bytes([x ^ y]) for x, y in zip(a, b)])

def incr_counter(Y):
    prefix = Y[:12]             # 96 bits nonce
    counter = int.from_bytes(Y[12:], 'big')
    counter = (counter + 1) % (2**32)
    return prefix + counter.to_bytes(4,'big')

def to_gcm_poly(value):
    # Convert to bytes (little-endian)
    value_bytes = value.to_bytes(16, 'little')
    
    # Reverse bits within each byte
    reflected_bytes = bytes(int(format(b, '08b')[::-1], 2) for b in value_bytes)
    
    # Convert back to integer
    reflected_value = int.from_bytes(reflected_bytes, 'big')
    
    return reflected_value

def zero_pad(data, block_length):
    if len(data)%block_length!=0:
        data = data + bytes([0]*(block_length-len(data)%block_length))
    else:
        pass
    return data


def gcm(ad:bytes([]), nonce:bytes([]), plaintext:bytes([]), mod:int, aes_key:bytes([])=None, h:GF2_k=None, ciphertext:bytes([])=None, test=False, tag:GF2_k=None, s:GF2_k=None):
    assert len(nonce) == 12

    block_length = 16


    # 1. Take your AES key and use it to encrypt a block of zeros:
    #    h := E(K, 0)

    if aes_key!=None:
        cipher_ecb = AES.new(aes_key, AES.MODE_ECB)

        h = cipher_ecb.encrypt(bytes([0]*block_length))
        h = GF2_k(to_gcm_poly(bytes_to_long(h)),mod)
    else:
        #ici on est dans la forgery
        assert h!=None
        assert isinstance(h, GF2_k)
        

    # 1. Zero-pad the bytes of associated data (AD) to be divisible by the
    #    block length. If it's already aligned on a block, leave it
    #    alone. Do the same with the ciphertext. Chain them together so you
    #    have something like:

    #        a0 || a1 || c0 || c1 || c2

    length_ad = len(ad)*8
    ad_copy = ad

    # ========== a0 || a1 génération ===========

    # Zero-pad in case
    ad = zero_pad(ad, block_length)
    # if len(ad)%block_length!=0:
    #     ad = ad + bytes([0]*(block_length-len(ad)%block_length))
    # else:
    #     pass

    assert len(ad)%block_length==0

    # ========== c0 || c1 || c2 génération ===========

    # ciphertext generation based on https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf (page 4)
    # I only considered the case where len(nonce) = 96 => assert len(nonce) == 12

    if aes_key!=None:
        ciphertext = b""
        Yi = nonce + (1).to_bytes(4, 'big')
        for index_block in range(0,len(plaintext),16):
            Yi = incr_counter(Yi)
            ciphertext += xor(cipher_ecb.encrypt(Yi), plaintext[index_block:min(index_block+16, len(plaintext))])
    else:
        # on est supposé avoir le bon ciphertext
        assert ciphertext !=None
        assert plaintext ==None
        
    ciphertext_copy = ciphertext

    # Zero-pad in case
    length_C = len(ciphertext)*8
    ciphertext = zero_pad(ciphertext, block_length)
    
    blocks = ad + ciphertext 

    #     2. Add one last block describing the length of the AD and the length
    #    of the ciphertext. Original lengths, not padded lengths; bit
    #    lengths, not byte lengths. Like this:
    #        len(AD) || len(C)

    len_block = length_ad.to_bytes(8, 'big') + length_C.to_bytes(8, 'big')

    blocks += len_block

    # 3. Take h and your string of blocks and do this:

    #     g := 0
    #     for b in bs:
    #         g := g + b
    #         g := g * h

    g=GF2_k(0,mod)
    for index_block in range(0,len(blocks),16):
        g = g + GF2_k(to_gcm_poly(bytes_to_long(blocks[index_block:index_block+16])),mod)
        g = g * h

    if test:
        polynome = []
        for index_block in range(0,len(blocks),16):
            polynome.append(GF2_k(to_gcm_poly(bytes_to_long(blocks[index_block:index_block+16])),mod))

    # 4. GCM takes a 96-bit nonce. Do this with it:

    #        s := E(K, nonce || 1)
    #        t := g + s

    if aes_key!=None:
        s = cipher_ecb.encrypt(nonce + (1).to_bytes(4, 'big'))
        t = g + GF2_k(to_gcm_poly(bytes_to_long(s)),mod)
    else:
        if tag != None:
            assert isinstance(tag, GF2_k)
            # si pas de tag présent on le calcule et on le renvoie
            s = g + tag
            return s
        else:
            # sinon on envoie s
            assert s != None
            assert isinstance(s, GF2_k)
            t = g + s

    if test:
        polynome.append(t)
    #  t is your tag. Convert it back to a block and ship it.
    # Python elimine les 0 MSB qd on fait hex(x)
        

    if test:
        return nonce.hex(), ad_copy.hex(), ciphertext_copy.hex(), format(to_gcm_poly(t.x), '032x'), Poly_GF2_k(polynome),h
    else:
        return nonce.hex(), ad_copy.hex(), ciphertext_copy.hex(), format(to_gcm_poly(t.x), '032x')

def recover(ad1:bytes([]), cipher1:bytes([]), tag1:bytes([]), ad2:bytes([]), cipher2:bytes([]), tag2:bytes([]), mod:int, poly1_ref=None, poly2_ref=None, h1_ref=None):
    block_length = 16

    tag1 = to_gcm_poly(bytes_to_long(tag1))
    tag2 = to_gcm_poly(bytes_to_long(tag2))

    poly1 = []
    poly2 = []

    # on va enlever le padding de zero
    length1 = (8*len(ad1)).to_bytes(8, 'big') + (8*len(cipher1)).to_bytes(8, 'big')
    length2 = (8*len(ad2)).to_bytes(8, 'big') + (8*len(cipher2)).to_bytes(8, 'big')
    # print(8*len(ad1), 8*len(cipher1), length1)
    # print(8*len(ad2), 8*len(cipher2), length2)

    # t0 = a0*h^6 + a1*h^5 + c0*h^4 + c1*h^3 + c2*h^2 + l0*h 
    ad1 = zero_pad(ad1, block_length)
    cipher1 = zero_pad(cipher1, block_length)

    blocks = ad1 + cipher1 + length1
    for k in range(0,len(blocks),16):
        poly1.append(GF2_k(to_gcm_poly(bytes_to_long(blocks[k:k+16])),mod))
    poly1.append(GF2_k(tag1,mod))

    ad2 = zero_pad(ad2, block_length)
    cipher2 = zero_pad(cipher2, block_length)

    blocks = ad2 + cipher2 + length2
    for k in range(0,len(blocks),16):
        poly2.append(GF2_k(to_gcm_poly(bytes_to_long(blocks[k:k+16])),mod))
    poly2.append(GF2_k(tag2,mod))

    poly1 = Poly_GF2_k(poly1)
    poly2 = Poly_GF2_k(poly2)
    poly_to_recover = poly1 + poly2

    if poly1_ref!=None and poly2_ref!=None and h1_ref!=None:
        # On vérifie que les polynomes sont les mêmes
        assert all([poly1.poly[k] == poly1_ref.poly[k] for k in range(len(poly1.poly))])
        assert all([poly2.poly[k] == poly2_ref.poly[k] for k in range(len(poly2.poly))])
        # on s'assure que la clé d'authentification est bien une racine du polynome à factoriser
        assert poly_to_recover(h1_ref) == GF2_k(0,mod)
    
    
    # now we need to factor f(y) = a0*y^6 +     a1*y^5 + (c0 + b0)*y^4 + (c1 + d0)*y^3 + (c2 + d1)*y^2 + (l0 + l1)*y + (t0 + t1)
    # because f(h) = 0 h the authentification key

    # on élimine les puissances
    polynomes_unsquared = Poly_GF2_k.square_free(poly_to_recover.monic())
    
    product_degree_1 = []
    for k in polynomes_unsquared:
        product_degree_1.append(Poly_GF2_k.distinct_degree(k[0], max_degree=1)[0][0])
    
    key_possibles = []
    for k in product_degree_1:
        if k._deg() == 1:
            # si le polynome est de degré 1, alors, on a pas besoin de le factoriser et donc 
            # la clé 1*y + a ==0 <=> a = y 
            # en bref la clé est le deuxieme coefficient
            key_possibles.append(k.poly[1])
        else:
            # on a un produit de polynome irreductible de degré 1
            # à factoriser avec Cantor-Zassenhaus
            polynomes_factorization = Poly_GF2_k.equal_degree_factorization(k,1)
            # on récupère la clé
            key_possibles = key_possibles + list(map(lambda x:x.poly[1],polynomes_factorization))

    if h1_ref!=None:
        assert h1_ref in key_possibles
        
    return key_possibles

def challenge(interface_encrypt, interface_decrypt, mod):

    # ==================== Nonce is repeated get 2 messages =======================

    plaintext1 = b"tototata"
    plaintext2 = b"tourloutout"

    res1 = interface_encrypt(plaintext1.hex())
    nonce1, ad1, cipher1, tag1 = res1["nonce"],res1["associated_data"], res1["ciphertext"], res1["tag"]

    res2 = interface_encrypt(plaintext2.hex())
    nonce2, ad2, cipher2, tag2 = res2["nonce"],res2["associated_data"], res2["ciphertext"], res2["tag"]

    assert nonce1 == nonce2

    cipher1 = bytes.fromhex(cipher1)
    cipher2 = bytes.fromhex(cipher2)
    tag1 = bytes.fromhex(tag1)
    tag2 = bytes.fromhex(tag2)
    ad1 = bytes.fromhex(ad1)
    ad2 = bytes.fromhex(ad2)
    nonce1 = bytes.fromhex(nonce1)

    # ==================== Factor polynomial to get possibles keys =======================

    key_possibles = recover(ad1, cipher1, tag1, ad2, cipher2, tag2, mod)

    # ==================== Get ciphertext of correct plaintext =======================
    plaintext_flag = b'give me the flag'
    res3 = interface_encrypt(plaintext_flag.hex())
    ciphertext_flag = bytes.fromhex(res3["ciphertext"])

    ad = b"CryptoHack"

    # on récupère le nonce derived secret value

    tag1 = GF2_k(to_gcm_poly(bytes_to_long(tag1)), mod)
    for h in key_possibles:
        # ========= on recalcule le tag de plaintext1 à partir de son ciphertext et de h ========
        # afin de récupérer la valeur s = E(K, nonce||1) = t - g = t + g = t + [ a0*h^6 + a1*h^5 + c0*h^4 + c1*h^3 + c2*h^2 + l0*h ]

        s = gcm(ad1, nonce1, None, mod, aes_key=None, h=h, ciphertext=cipher1, tag=tag1)

        # ========== Mainteant qu'on a : s et h, on peut authentifier tout plaintext dont on connait le ciphertext ===================
        nonce_try, associated_data_try, ciphertext_try, tag_try = gcm(ad, nonce1, None, mod, aes_key=None, h=h, ciphertext=ciphertext_flag, s=s)
        res = interface_decrypt(nonce_try, ciphertext_try, tag_try, associated_data_try)

        if "error" not in res.keys():
            flag = bytes.fromhex(res["plaintext"])
            break
    return flag