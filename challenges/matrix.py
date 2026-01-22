import random
import os 
from sage.all import Matrix, GF, identity_matrix
import numpy as np

P = 2
N = 50
E = 31337

FLAG = b'crypto{bla}'


from Crypto.Util.number import bytes_to_long, long_to_bytes


def bytes_to_binary(s):
    bin_str = ''.join(format(b, '08b') for b in s)
    bits = [int(c) for c in bin_str]
    return bits

def generate_mat():
    while True:
        msg = bytes_to_binary(FLAG)
        msg += [random.randint(0, 1) for _ in range(N*N - len(msg))]

        rows = [msg[i::N] for i in range(N)]
        mat = Matrix(GF(2), rows)

        if mat.determinant() != 0 and mat.multiplicative_order() > 10^12:
            # if mat.determinant() != 0 => matrice inversible
            #  mat.multiplicative_order() > 10^12 => mat^k = I k>10^12 
            return mat

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

def save_matrix(M, fname):
    open(fname, 'w').write('\n'.join(''.join(str(x) for x in row) for row in M))


def fast_exponentiation(matrix, exponent):
    result = identity_matrix(GF(P), N)
    while exponent > 0:
        if exponent % 2 == 1:
            result *= matrix
        matrix *= matrix
        exponent //= 2
    return result

"""
mat = generate_mat()

ciphertext = mat^E #actual encryption taking place
save_matrix(ciphertext, 'flag.enc')
"""

if __name__ == "__main__":

    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    cipher_flag_path = os.path.join(folder, 'flag_matrix.enc')

    ciphertext = load_matrix(cipher_flag_path)

    matrix = np.array((ciphertext ** (-pow(E, -1, ciphertext.multiplicative_order())%ciphertext.multiplicative_order())).inverse())
    flag = bytes(np.packbits(np.array(matrix).T.flatten().astype(np.uint8)))
    index_end = flag.index(b"}")
    assert flag[:index_end+1] == b'crypto{there_is_no_spoon_66eff188}'
