#!/usr/bin/env python3

from os import urandom


FLAG = b'crypto{?????????????????????????????}'


def bytes_to_words(b):
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

def word(x):
    # parait cohérent, on fait une troncature à 2**32 
    return x % (2 ** 32)

def words_to_bytes(w):
    return b''.join([i.to_bytes(4, 'little') for i in w])

def xor(a, b):
    # ok 
    return b''.join([bytes([x ^ y]) for x, y in zip(a, b)])


def rotate(x, n):
    # les 0xffffffff à droites sont inutiles mais c'est normales
    # & 0xffffffff <=> mod 2**32
    # on dirait qu'il y a perte d'information mais en realité c'est une juste une permutation de bit
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff) 

class ChaCha20:
    def __init__(self):
        self._state = []

    def _inner_block(self, state):
        self._quarter_round(state, 0, 4, 8, 12)
        self._quarter_round(state, 1, 5, 9, 13)
        self._quarter_round(state, 2, 6, 10, 14)
        self._quarter_round(state, 3, 7, 11, 15)

        # C'est bon ca ? On dirait ils font le decalage non pas horizontalement mais verticalement
        # a c'est chacha20
        self._quarter_round(state, 0, 5, 10, 15)
        self._quarter_round(state, 1, 6, 11, 12)
        self._quarter_round(state, 2, 7, 8, 13)
        self._quarter_round(state, 3, 4, 9, 14)

    def _quarter_round(self, x, a, b, c, d):
        # parait cohérent non ?
        # modification in place de self._state
        x[a] = word(x[a] + x[b]); x[d] ^= x[a]; x[d] = rotate(x[d], 16)
        x[c] = word(x[c] + x[d]); x[b] ^= x[c]; x[b] = rotate(x[b], 12)
        x[a] = word(x[a] + x[b]); x[d] ^= x[a]; x[d] = rotate(x[d], 8)
        x[c] = word(x[c] + x[d]);x[b] ^= x[c]; x[b] = rotate(x[b], 7)
    
    def _setup_state(self, key, iv):
        # Tout semble bon ici c'est du chacha20 classique
        self._state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

        # pas de forcing sur la taile de la key ?
        self._state.extend(bytes_to_words(key))
        self._state.append(self._counter)
        self._state.extend(bytes_to_words(iv))

    def decrypt(self, c, key, iv):
        return self.encrypt(c, key, iv)

    def encrypt(self, m, key, iv):
        c = b''
        self._counter = 1

        for i in range(0, len(m), 64):
            # initialisation avant chaque 
            self._setup_state(key, iv)
            for j in range(10):
                self._inner_block(self._state)

            # me parait cohérent 64 bytes = 512 bits XOR 512 bits du state
            # no feed forward on dirait ce qui est à être exploité alalalalah FUCK
            # relouuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu
            c += xor(m[i:i+64], words_to_bytes(self._state))

            # le compteur est bien incrémenté
            self._counter += 1
        
        return c
    
class Reverse_vuln_chacha20:
    def reverse_rotate(self, rot, n):
        return (rot >> n) + ((rot % 2**n) << (32-n))

    def reverse_quarter_round(self, state_rev, a, b, c, d):
        state_rev[b] = self.reverse_rotate(state_rev[b], 7)
        state_rev[b] ^= state_rev[c]
        state_rev[c] =  word(state_rev[c] - state_rev[d])

        state_rev[d] = self.reverse_rotate(state_rev[d], 8)
        state_rev[d] ^= state_rev[a]
        state_rev[a] =  word(state_rev[a] - state_rev[b])

        state_rev[b] = self.reverse_rotate(state_rev[b], 12)
        state_rev[b] ^= state_rev[c]
        state_rev[c] =  word(state_rev[c] - state_rev[d])

        state_rev[d] = self.reverse_rotate(state_rev[d], 16)
        state_rev[d] ^= state_rev[a]
        state_rev[a] =  word(state_rev[a] - state_rev[b])

    def reverse_inner_round(self, state_rev): 
        self.reverse_quarter_round(state_rev, 3, 4, 9, 14)
        self.reverse_quarter_round(state_rev, 2, 7, 8, 13)
        self.reverse_quarter_round(state_rev, 1, 6, 11, 12)
        self.reverse_quarter_round(state_rev, 0, 5, 10, 15)

        self.reverse_quarter_round(state_rev, 3, 7, 11, 15)
        self.reverse_quarter_round(state_rev, 2, 6, 10, 14)
        self.reverse_quarter_round(state_rev, 1, 5, 9, 13)
        self.reverse_quarter_round(state_rev, 0, 4, 8, 12)

    def decrypt_key(self, cipher, message):
        # on prend le keystream du premier block pour retrouver la clé
        keystream = xor(cipher, message)[0:512//8]
        key = b''

        state_rev = bytes_to_words(keystream).copy()  
        for j in range(10):
            self.reverse_inner_round(state_rev)

        key = words_to_bytes(state_rev[4:12])
        return key


if __name__ == '__main__':
    """
    En gros, l'implentation manque la dernière étape qui est le feed forward 
    a cause de ca, on peut remonter pas à pas dans les rounds de chacha20 jusqu'à retomber 
    au state initial et en extraire la key 

    Pour faire ca il nous suffit de reverse le 1er block chacha20. Dès qu'on a la key on peut reproduire le keystream original pour 
    déchiffrer le message. 

    Le msg suivant et son chiffré nous permettent d'extraire la key. Tout le code est dans la classe Reverse_vuln_chacha20

    msg = b'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula.'
    msg_enc = bytes.fromhex('f3afbada8237af6e94c7d2065ee0e221a1748b8c7b11105a8cc8a1c74253611c94fe7ea6fa8a9133505772ef619f04b05d2e2b0732cc483df72ccebb09a92c211ef5a52628094f09a30fc692cb25647f')
    key_uncipher = decrypt_key(msg_enc, msg)

    Dès qu'on a la clé, on peut déchiffrer le message (avec le bon iv évidemment)
    flag = c.decrypt(flag_enc, key_uncipher, iv2)
    assert flag == b'crypto{M1x1n6_r0und5_4r3_1nv3r71bl3!}'
    """

    # ================== Test local ===========
    msg = b'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula.'

    key = urandom(32) #32*8 = 256 bit cohérent (8 mots) 
    iv1 = urandom(12) #12*8 = 96 bit cohérent (3 mots)
    iv2 = urandom(12) #12*8 = 256 bit cohérent (3 mots)

    c = ChaCha20()
    msg_enc = c.encrypt(msg, key, iv1)
    
    # ================================ on reverse chacha20 ================================
    # il n'y a pas d'étape de feed forwrad donc on peut revenir dans l'étét du stream cipher
    rev = Reverse_vuln_chacha20()

    key_uncipher = rev.decrypt_key(msg_enc, msg)
    assert key == key_uncipher
    assert msg_enc == c.encrypt(msg, key_uncipher, iv1)
    assert c.decrypt(msg_enc, key_uncipher, iv1) == msg
    
    # ============== Challenge =====================

    iv1 = bytes.fromhex('e42758d6d218013ea63e3c49')
    iv2 = bytes.fromhex('a99f9a7d097daabd2aa2a235')

    msg = b'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula.'
    msg_enc = bytes.fromhex('f3afbada8237af6e94c7d2065ee0e221a1748b8c7b11105a8cc8a1c74253611c94fe7ea6fa8a9133505772ef619f04b05d2e2b0732cc483df72ccebb09a92c211ef5a52628094f09a30fc692cb25647f')
    flag_enc =  bytes.fromhex('b6327e9a2253034096344ad5694a2040b114753e24ea9c1af17c10263281fb0fe622b32732')

    rev = Reverse_vuln_chacha20()
    key_uncipher = rev.decrypt_key(msg_enc, msg)

    c = ChaCha20()
    assert msg_enc == c.encrypt(msg, key_uncipher, iv1)
    assert c.decrypt(msg_enc, key_uncipher, iv1) == msg

    flag = c.decrypt(flag_enc, key_uncipher, iv2)
    assert flag == b'crypto{M1x1n6_r0und5_4r3_1nv3r71bl3!}'




