from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa import ellipticcurve, curves
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint
from tonellishanks import tonellishanks  
from hashlib import sha1



import os,sys

# Ajout du répertoire eliptic curve
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from ecdsa_biais_attack import challenge, samples

def interface():

    sig1={'message': 'I have hidden the secret flag as a point of an elliptic curve using my private key.', 'r': '0x91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae', 's': '0x1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d'}
    sig2={'message': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', 'r': '0xe8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c', 's': '0x582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8'}
    sig3={'message': 'Good luck!', 'r': '0x566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6', 's': '0x9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba'}

    return sig1, sig2, sig3


if __name__ == "__main__":
    G = generator_256
    q = G.order()

    flag = (16807196250009982482930925323199249441776811719221084165690521045921016398804, 72892323560996016030675756815328265928288098939353836408589138718802282948311)

    signatures = samples(interface)
    private_key = challenge(hash_function_message=sha1, signatures = signatures, bit_length_prefix=96, biais=0)

    pubkey_lattice = Public_key(G, private_key*G)

    public_key_data = (48780765048182146279105449292746800142985733726316629478905429239240156048277, 74172919609718191102228451394074168154654001177799772446328904575002795731796)
    pubkey_lattice_expected = Public_key(G, ellipticcurve.Point(curves.NIST256p.curve, public_key_data[0], public_key_data[1]))

    if pubkey_lattice != pubkey_lattice_expected:
        raise Exception("Mauvaise clé privée")
    
    T_point = ellipticcurve.Point(curves.NIST256p.curve, flag[0], flag[1])
    Q = pow(private_key,-1, q) * T_point

    flag = long_to_bytes(int(Q.x()))

    print(private_key)
    print(flag)
    assert flag == b'crypto{3mbrac3_r4nd0mn3ss}'


    


