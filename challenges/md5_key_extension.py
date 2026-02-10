import struct
import math
from hashlib import md5

# ========================
# MD5 primitives
# ========================

def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xffffffff

# Constantes MD5
S = [
     7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
     5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
     4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
     6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
]

K = [int(abs(math.sin(i + 1)) * 2**32) & 0xffffffff for i in range(64)]

def md5_compress(state, block):
    a, b, c, d = state
    M = struct.unpack('<16I', block)

    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5*i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3*i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7*i) % 16

        tmp = (a + f + K[i] + M[g]) & 0xffffffff
        a, d, c, b = d, c, b, (b + left_rotate(tmp, S[i])) & 0xffffffff

    return (
        (state[0] + a) & 0xffffffff,
        (state[1] + b) & 0xffffffff,
        (state[2] + c) & 0xffffffff,
        (state[3] + d) & 0xffffffff,
    )

# ========================
# Padding MD5
# ========================

def md5_padding(length_bytes):
    bit_len = length_bytes * 8
    padding = b'\x80'
    # on s'arrete des qu'on a atteint 448 bit
    while (length_bytes + len(padding)) % 64 != 56:
        padding += b'\x00'

    # on encode sur 64 bit la longeur du message
    padding += struct.pack('<Q', bit_len)
    return padding

# ========================
# Length Extension
# ========================

def md5_length_extension(hash_hex, len_B1, B2):
    # Reconstituer l'état interne depuis le hash
    state = struct.unpack('<4I', bytes.fromhex(hash_hex))

    # Padding de B1 (qu'on ne connaît pas)
    pad_B1 = md5_padding(len_B1)

    # Longueur totale AVANT padding final
    total_len = len_B1 + len(pad_B1) + len(B2)

    # Traiter B2 bloc par bloc
    data = B2
    if len(data) % 64 != 0:
        data += md5_padding(total_len)

    for i in range(0, len(data), 64):
        state = md5_compress(state, data[i:i+64])

    return struct.pack('<4I', *state).hex()

B1 = b"A" * 64
hash_B1 =  md5(B1).hexdigest()  # exemple
len_B1 = len(B1)                          # en octets
B2 = b"admin=true"

new_hash_extended = md5_length_extension(hash_B1, len_B1, B2)
real_hash_extended = md5(B1+md5_padding(len_B1)+B2).hexdigest()
assert new_hash_extended == real_hash_extended