from hashlib import sha1, sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint

import numpy as np
from fpylll import IntegerMatrix, LLL
import math

def generer_cle():
    print("\n==========================================================================================")
    print("==========================================================================================")
    G = generator_256       # générateur de la courbe
    ordre = G.order()       # ordre du générateur
    secret = randint(1, ordre-1)  # clé privée aléatoire
    pub = Public_key(G, secret * G)
    priv = Private_key(pub, secret)
    return pub, priv

# Signature déterministe inspirée de RFC 6979
def signer_ecdsa_sha1_nonce(message, cle_privee, hash_function_message):

    h = hash_function_message(message.encode()).digest()

    #nonce avec sha1
    k = sha1(long_to_bytes(cle_privee.secret_multiplier) + h).digest()
    
    signature = cle_privee.sign(bytes_to_long(h), bytes_to_long(k))
    return {"message": message, "r": hex(signature.r), "s": hex(signature.s)}

# Signature déterministe inspirée de RFC 6979
def signer_ecdsa_nonce_with_10_MSB_biaised(message, cle_privee, hash_function_message):

    h = hash_function_message(message.encode()).digest()

    #nonce avec sha1
    shift = 256 - 10
    k = sha256(long_to_bytes(cle_privee.secret_multiplier) + h).digest()

    k = (0b1001110101 << (shift)) | (bytes_to_long(k) & ((1 << shift) - 1))
    
    signature = cle_privee.sign(bytes_to_long(h),k)
    return {"message": message, "r": hex(signature.r), "s": hex(signature.s)}

# Exemple d'utilisation avec phrases de Victor Hugo
def exemple_signature(hash_function_message, nb_signatures, signing_function):
    pub, priv = generer_cle()
    print(f"\nKey generated: {priv.secret_multiplier}")

    cle_publique = (int(pub.point.x()), int(pub.point.y()))

    messages = [
        "La liberté commence où l'ignorance finit.",
        "L'avenir est une porte, le passé en est la clé.",
        "La vie est une fleur dont l'amour est le miel.",
        "Rien n'est plus puissant qu'une idée dont l'heure est venue.",
        "Le bonheur suprême de la vie est la conviction d'être aimé.",
        "La conscience est la lumière de l'intelligence.",
        "Aimer, c'est agir.",
        "Celui qui ouvre une porte d'école ferme une prison.",
        "Le travail adoucit les mœurs.",
        "La mélancolie, c'est le bonheur d'être triste.",
        "Il n'y a rien de plus fort qu'une âme libre.",
        "La pensée est un acte, la parole en est l'écho.",
        "L'espérance est la plus grande des forces humaines.",
        "La nuit produit parfois des lumières invisibles au jour.",
        "Le rire est le soleil qui chasse l'hiver du visage humain.",
        "Les mots sont des êtres vivants.",
        "Ceux qui vivent sont ceux qui luttent.",
        "La vérité est semblable au soleil.",
        "L'amour est une partie de l'âme elle-même.",
        "La beauté commence au moment où vous décidez d'être vous-même.",
        "L'homme est fait pour contempler et agir.",
        "Le cœur humain a des secrets que la raison ignore.",
        "La pensée éclaire le monde comme le soleil éclaire la terre.",
        "Le silence est parfois la plus éloquente des paroles.",
        "La grandeur d'un homme se mesure à sa bonté.",
        "La souffrance forge les esprits les plus forts.",
        "L'espérance est un rêve éveillé.",
        "Les grandes passions élèvent l'âme.",
        "Le devoir est la loi du cœur.",
        "La justice est la vérité en action.",
        "La vie est un combat qu'il faut mener avec courage.",
        "La liberté est le droit de dire non.",
        "Chaque homme porte en lui une lumière.",
        "Le temps est un fleuve qui emporte tout.",
        "La mémoire est une lampe dans l'obscurité.",
        "Le génie est une longue patience.",
        "La parole est la voix de l'âme.",
        "L'ombre est nécessaire pour comprendre la lumière.",
        "Les rêves construisent le réel.",
        "La solitude est parfois la meilleure des compagnies.",
        "La vérité finit toujours par apparaître.",
        "Le courage est une forme de dignité.",
        "La pensée libre est une révolution silencieuse.",
        "La bonté est la plus grande des richesses.",
        "L'homme devient ce qu'il pense.",
        "Le regard révèle ce que les mots cachent.",
        "L'âme grandit à travers les épreuves.",
        "La lumière intérieure ne s'éteint jamais.",
        "La justice est une étoile qui guide les hommes.",
        "La vie est une énigme que l'amour éclaire."
    ]   
    signing_function(messages[0], priv, hash_function_message)
    
    signatures = [signing_function(msg, priv, hash_function_message) for msg in messages[:nb_signatures]]

    return signatures

def construct_lattice(P_Im, T, A, B_p, B_last):
    B = np.concatenate((P_Im, T.reshape(1, -1), A.reshape(1, -1)), axis=0)
    B = np.concatenate((B, B_p.reshape(-1, 1), B_last.reshape(-1, 1)), axis=1)
    return B

def reduce(B):
    B_ = IntegerMatrix.from_matrix(B)
    LLL.reduction(B_)
    return np.array([list(row) for row in B_], dtype=object)

def test_reduction():
    # ================= Probleme du CVP avec scaling facteur =================
    order_curve = 401
    m = 3
    b= 20

    P_Im = np.eye(m, dtype=object)*order_curve**2
    T = np.array([143,293,304])*order_curve
    A = np.array([62,300,86])*order_curve

    B_p = np.zeros(m+2, dtype=object)
    B_p[m] = b

    B_last = np.zeros(m+2, dtype=object)
    B_last[m+1] = b*order_curve

    B = construct_lattice(P_Im, T, A, B_p, B_last)
    B_LLL = reduce(B)
    assert np.array_equal(B_LLL[1], np.array([-6015, -4812, -6416,  1840,  8020]))


def recover_known_msb(bit_length_prefix, T_i, order_curve, signatures, b):
    # signatures [{"z":hash, "r":, "s"}]

    Z = np.array(list(map(lambda x:x["z"], signatures)), dtype=object)  
    R = np.array(list(map(lambda x:x["r"], signatures)), dtype=object)
    S_inv = np.array(list(map(lambda x:pow(x["s"],-1,order_curve), signatures)), dtype=object)
    m = len(signatures)

    # ========= construction lattice avec scaling facteur =============
    P_Im = np.eye(m, dtype=object)*order_curve**2

    T = S_inv * R * order_curve

    A = (2**(int(math.log2(order_curve)) + 1 - bit_length_prefix)*T_i - S_inv * Z) * order_curve
    
    B_p = np.zeros(m+2, dtype=object)
    B_p[m] = b

    B_last = np.zeros(m+2, dtype=object)
    B_last[m+1] = b * order_curve

    print("\n======== Lattice construction =========")
    B = construct_lattice(P_Im, T, A, B_p, B_last)
    print("\n======== Lattice reduction =========")
    B_LLL = reduce(B)
    
    return B_LLL

def samples(interface, hash_function_message=None, 
              nb_signatures=None, signing_function=None):
    # this is to ensure a clean way to generate signatures
    # no matter matter is they're simulated our imposed (ctf etc.)
    # in this case you need to redefine your own interface like this
    # interface should output :
    # list[
    #      {"message":"message1", "r":"0x...", "s":"0x...""."},
    #      {"message":"message2", "r":"0x...", "s":"0x...""."},
    #      ...
    #      ]
    # then you call signatures = samples(interface)

    if (signing_function!=None and hash_function_message!=None):
        return interface(hash_function_message, nb_signatures, 
                                                        signing_function)
    else:
        return interface()



def challenge(hash_function_message, signatures, bit_length_prefix, biais):

    nb_signatures = len(signatures)

    print(f"\nNb of signatures asked : {nb_signatures}, the biais is of {bit_length_prefix} MSB length")
    biais_bin = format(biais, f"0{bit_length_prefix}b")
    print(f"biais is fixed to {biais_bin}")

    G = generator_256
    order_curve = int(G.order())

    signatures = [{"z":int(hash_function_message(sig["message"].encode()).hexdigest(),16), 
                   "r":int(sig["r"],16), 
                   "s":int(sig["s"],16)
                   } for sig in signatures]

    # ========== les x premiers bits sont biaisés =============
    b = 2**(256-bit_length_prefix)

    # le biais sont les bits imposés
    T_i = [biais]*nb_signatures

    T_i = np.array(T_i, dtype=object)

    # on utilise SHA1 donc on sait que les 96 premiers bit du nonce sont à 0
    B_LLL = recover_known_msb(bit_length_prefix, T_i, order_curve, signatures, b)

    # on teste si on a u ou -u
    if B_LLL[1][-1] == -b*order_curve:
        key = B_LLL[1][-2] // b
    elif B_LLL[1][-1] == b*order_curve:
        key = (-B_LLL[1][-2] // b)%order_curve
    else:
        raise Exception()

    return key

if __name__ == "__main__":
    # ================== Test Reduction ==================
    test_reduction()

    # ================== Test Biaised signatures sha1 nonce leading 96 bit 0 ==================
    interface = exemple_signature
    signatures = samples(interface, hash_function_message=sha256, nb_signatures=3, signing_function=signer_ecdsa_sha1_nonce)

    key = challenge(hash_function_message=sha256, signatures = signatures, bit_length_prefix=96, biais=0)
    print(f"\nkey recovered: {key}")

    # ================== Test Biaised signatures sha256 leading 10 bit fixed to 0b1001110101 ==================
    interface = exemple_signature

    biais = int("1001110101", 2)
    signatures = samples(interface, hash_function_message=sha256, nb_signatures=32, signing_function=signer_ecdsa_nonce_with_10_MSB_biaised)

    key = challenge(hash_function_message=sha256, signatures=signatures, bit_length_prefix=10, biais=biais)
    print(f"\nkey recovered: {key}")
