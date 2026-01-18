import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *
import json

r = remote('socket.cryptohack.org', 13405)

# 2^128 collision protection!
BLOCK_SIZE = 32

# miam DUAL ECERBG
# Nothing up my sleeve numbers (ref: Dual_EC_DRBG P-256 coordinates)
# https://en.wikipedia.org/wiki/Dual_EC_DRBG
W = [0x6b17d1f2, 0xe12c4247, 0xf8bce6e5, 0x63a440f2, 0x77037d81, 0x2deb33a0, 0xf4a13945, 0xd898c296] #Px P256  & DUAL ECRBG
X = [0x4fe342e2, 0xfe1a7f9b, 0x8ee7eb4a, 0x7c0f9e16, 0x2bce3357, 0x6b315ece, 0xcbb64068, 0x37bf51f5] #Py P256  & DUAL ECRBG
Y = [0xc97445f4, 0x5cdef9f0, 0xd3e05e1e, 0x585fc297, 0x235b82b5, 0xbe8ff3ef, 0xca67c598, 0x52018192] #Qx DUAL
Z = [0xb28ef557, 0xba31dfcb, 0xdd21ac46, 0xe2a91e3c, 0x304f44cb, 0x87058ada, 0x2cb81515, 0x1e610046] #Qy Dual ECRBG

# Lets work with bytes instead!
W_bytes = b''.join([x.to_bytes(4,'big') for x in W])
X_bytes = b''.join([x.to_bytes(4,'big') for x in X])
Y_bytes = b''.join([x.to_bytes(4,'big') for x in Y])
Z_bytes = b''.join([x.to_bytes(4,'big') for x in Z])

def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)

def blocks(data):
    return [data[i:(i+BLOCK_SIZE)] for i in range(0,len(data),BLOCK_SIZE)]

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

def rotate_left(data, x):
    x = x % BLOCK_SIZE
    return data[x:] + data[:x]

def rotate_right(data, x):
    x = x % BLOCK_SIZE
    return  data[-x:] + data[:-x]

def scramble_block(block):
    for _ in range(40):
        block = xor(W_bytes, block)
        block = rotate_left(block, 6)
        block = xor(X_bytes, block)
        block = rotate_right(block, 17)
    return block

def cryptohash(msg):
    initial_state = xor(Y_bytes, Z_bytes)
    msg_padded = pad(msg)
    msg_blocks = blocks(msg_padded)
    for i,b in enumerate(msg_blocks):
        mix_in = scramble_block(b)
        for _ in range(i):
            mix_in = rotate_right(mix_in, i+11)
            mix_in = xor(mix_in, X_bytes)
            mix_in = rotate_left(mix_in, i+6)
        initial_state = xor(initial_state,mix_in)
    return initial_state.hex()


def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

def resolve_challenge(interface_challenge):
    pass

def position_depart(position_mix_scramble):
    init = position_mix_scramble
    for _ in range(40):
        init -= 17
        init += 6
    return init%32

if __name__ == "__main__":
    print(r.readline())

    block = os.urandom(32)

    # =============== Démo collision =====================
    # il y avait plus simple avec le padding
    
    # ma stratégie était d'identifier la position_depart(position_mix_scramble)
    # la position de départ d'un octet dans bloc par rapoort à sa position après toutes les transformations
    # avec deux blocs de fin xorré xor(initial_state,mix_in), on peut ainsi modifié deux octets qui xorés vont donner le même résultat
    # j'ai ainsi identifié pour le 1et et 2ème bloc qu'elle était les emplacements qui modifiait uniquement le byte de fin 
    # 7ème position (position_depart(-1) == 7)  pour le 1er bloc et 2ème position pour le 2ème 
    # car des transformations supplémentaire sont effectués avec :
        #     for _ in range(i):
        #     mix_in = rotate_right(mix_in, i+11)
        #     mix_in = xor(mix_in, X_bytes)
        #     mix_in = rotate_left(mix_in, i+6)
        # initial_state = xor(initial_state,mix_in)
    # sur les blocs dont l'indice est au dessus de 0
    # attention position_depart(position_mix_scramble) caclule la position de depart d'un octet par rapport à scramble_block
    # de fait pour les deuxième bloc il faut aussi reverse à la main les opérations suivantes : (i=1) [ du bas vers le haut]
    #     mix_in = rotate_right(mix_in, i+11) # 6 => -6 => position_depart(-6) ==2
    #     mix_in = rotate_left(mix_in, i+6) # -1 => 6
    # c'ets pourquoi on tombe sur la 2ème position

    # on identifie que la différence de transformations à base de XOR entre le dernier octet du 1er bloc et le dernier du 
    # 2nd block est un simple XOR à savoir mix_in = xor(mix_in, X_bytes)
    # à ce moment la, le byte qui nous interresse est le 6ème
    # c1 et c2 désigne les blocs apères transformations 
    # c1_apres[-1] == c2_apres[-1] <=> c1_avant[7] XOR truc1 = c2_avant[2] XOR truc2 XOR X_bytes[6] 

    # truc1 et truc2 représentent les permutations effectuées par scramble_block 
    # elles sont les mêmes car scramble_block est appliquée similairement aux diffèrents blocs
    # donc :
    # c1_apres[-1] == c2_apres[-1] <=> c1_avant[7] = c2_avant[2] XOR X_bytes[6] 

    # On a donc à chosir deux bytes arbitraires pour c1_avant[7] et calculer les c2_avant[2] correspondants

    block_1 = b"a"
    block_2 = bytes([block_1[0] ^ X_bytes[6]])
    data_first = block[:7]+block_1+block[8:]+block[:2]+block_2+block[3:]
    print(cryptohash(data_first))

    block_1 = b"b"
    block_2 = bytes([block_1[0] ^ X_bytes[6]])
    data_second = block[:7]+block_1+block[8:]+block[:2]+block_2+block[3:]
    print(cryptohash(data_second))

    assert data_first != data_second
    assert cryptohash(data_first) == cryptohash(data_second)

    # ================ Cryptohack challenge ================
    r.sendline(json.dumps({"m1":data_first.hex(), "m2":data_second.hex()}).encode())
    
    r.readline()
    res = r.readline()
    flag = res.decode().split("flag: ")[-1][:-3]
    assert flag == "crypto{Always_add_padding_even_if_its_a_whole_block!!!}"

