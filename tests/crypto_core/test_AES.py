from crypto_core.AES import (matrix2bytes,
                                add_round_key, 
                                sub_bytes, 
                                inv_mix_columns, 
                                inv_shift_rows, 
                                decrypt, 
                                encrypt, 
                                S_BOX, 
                                INV_S_BOX)

def test_matrix2bytes():
    matrix = [
            [99, 114, 121, 112],
            [116, 111, 123, 105],
            [110, 109, 97, 116],
            [114, 105, 120, 125],
            ]

    assert matrix2bytes(matrix)==b"crypto{inmatrix}"

def test_add_round_key():
    # ======= round key ===========
    state = [
        [206, 243, 61, 34],
        [171, 11, 93, 31],
        [16, 200, 91, 108],
        [150, 3, 194, 51],
    ]

    round_key = [
        [173, 129, 68, 82],
        [223, 100, 38, 109],
        [32, 189, 53, 8],
        [253, 48, 187, 78],
    ]

    add_round_key(state, round_key)
    assert matrix2bytes(state)==b'crypto{r0undk3y}'

def test_sub_bytes():
    # ======= subbytes ===========
    state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
    ]

    sub_bytes(state, sbox=INV_S_BOX)
    assert matrix2bytes(state)==b"crypto{l1n34rly}"

def test_inv_mix_columns_and_inv_shift_rows():
    # ===== inv mix columns and shift rows ======
    state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
    ]

    inv_mix_columns(state)
    inv_shift_rows(state)
    assert matrix2bytes(state)==b'crypto{d1ffUs3R}'

def test_encryption():
    # ============ decryption =============
    n_rounds = 10
    key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
    ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

    ciphertext_v2 = encrypt(key, b'crypto{MYAES128}', n_rounds)
    assert ciphertext==ciphertext_v2

def test_decryption():
    # ============ decryption =============
    n_rounds = 10
    key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
    ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

    uncipher = decrypt(key, ciphertext, n_rounds)
    assert uncipher==b'crypto{MYAES128}'

