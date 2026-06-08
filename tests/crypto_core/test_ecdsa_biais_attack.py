from crypto_core.ecdsa_biais_attack import (generer_cle, 
                                            signer_ecdsa_sha1_nonce, 
                                            signer_ecdsa_nonce_with_10_MSB_biaised,
                                            exemple_signature,
                                            construct_lattice,
                                            reduce,
                                            recover_known_msb,
                                            samples,
                                            challenge)

import numpy as np
from hashlib import sha1, sha256
import pytest

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


@pytest.mark.parametrize("hash_function_message, nb_signatures, signing_function, bit_length_prefix, biais", [
    pytest.param(sha256, 3, signer_ecdsa_sha1_nonce, 96, 0, id="Simulation utilisation de SHA1 dans le calcul du nonce"), 
    pytest.param(sha256, 32, signer_ecdsa_nonce_with_10_MSB_biaised, 10, int("1001110101", 2), id="Simulation biais faible au debut mais fixe type side channels"), 
])
def test_ecdsa_biais(hash_function_message, nb_signatures, signing_function, bit_length_prefix, biais):
    interface = exemple_signature
    signatures, priv = samples(interface, hash_function_message=hash_function_message, nb_signatures=nb_signatures, signing_function=signing_function)

    key = challenge(hash_function_message=hash_function_message, signatures = signatures, bit_length_prefix=bit_length_prefix, biais=biais)
    
    assert key == priv.secret_multiplier

