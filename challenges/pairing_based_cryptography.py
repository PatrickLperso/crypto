from py_ecc.optimized_bn128 import G1, G2, multiply, pairing
from py_ecc.optimized_bn128 import (
    FQ, FQ2, FQ12,
    is_on_curve,
    b,
    b2,
    b12
)

import os
from tqdm import tqdm

def gen_test(is_true):
    x = int(os.urandom(8).hex(), 16)
    y = int(os.urandom(8).hex(), 16)
    bias = 1 if is_true else int(os.urandom(2).hex(), 16)
    xG = multiply(G1, x)
    yG = multiply(G2, y)
    zG = pairing(yG, multiply(xG, bias))
    return xG, yG, zG

def make_G1_proj(X, Y, Z):
    P = (FQ(X), FQ(Y), FQ(Z))
    assert is_on_curve(P, b)
    return P

def make_G2_proj(X, Y, Z):
    P = (
        FQ2(X),  # [x0, x1]
        FQ2(Y),  # [y0, y1]
        FQ2(Z),  # [z0, z1]
    )
    assert is_on_curve(P, b2)
    return P

# challenges = []

# for bit in bin(int(FLAG.hex(),16))[2:]:
#     xG, yG, zG = gen_test(int(bit))
#     challenges.append([xG, yG, zG])

# with open("output.txt", "w") as f:
#     for chal in challenges:
#         # Note: in your solution script, you can read each line by calling eval() on it
#         f.write(str(chal))
#         f.write("\n")

if __name__ == "__main__":
    flag = ""

    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    with open(os.path.join(folder, "output_pairing.txt"), "r") as f:
        for _, line in enumerate(tqdm(f)):
            A, B, C = eval(line)

            xG = make_G1_proj(A[0], A[1], A[2])
            # attention ici c'est des tuples
            yG = make_G2_proj(B[0], B[1], B[2])
            
            if pairing(yG, xG) == FQ12(C):
                flag +="1"
            else:
                flag +="0"

    n = int(flag,2)
    flag = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    assert flag == b'crypto{Pa1rings_R_Str0ng}'