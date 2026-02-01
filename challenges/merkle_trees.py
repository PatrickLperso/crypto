from hashlib import sha256
import os

FLAG = b"crypto{??????????????????????????????}"

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)

def gen_test(is_true):
    a = hash256(os.urandom(8))
    b = hash256(os.urandom(8))
    c = hash256(os.urandom(8))
    d = hash256(os.urandom(8))
    bias = b"" if is_true else os.urandom(8)
    left = merge_nodes(a, b+bias)
    right = merge_nodes(c, d)
    root = merge_nodes(left, right)
    return a.hex(), b.hex(), c.hex(), d.hex(), root.hex()

# challenges = []

# for bit in bin(int(FLAG.hex(),16))[2:]:
#     a, b, c, d, root = gen_test(int(bit))
#     challenges.append([a, b, c, d, root])

if __name__ == "__main__":
    flag = ""

    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")
    with open(os.path.join(folder, "output_merkletree.txt"), "r") as f:
        for line in f:
            a,b,c,d,root = eval(line)
            a = bytes.fromhex(a)
            b = bytes.fromhex(b)
            c = bytes.fromhex(c)
            d = bytes.fromhex(d)
            if merge_nodes(merge_nodes(a, b), merge_nodes(c, d)).hex() == root:
                flag +="1"
            else:
                flag +="0"

    n = int(flag,2)
    flag = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    assert flag == b'crypto{U_are_R3ady_For_S4plins_ch4lls}'

