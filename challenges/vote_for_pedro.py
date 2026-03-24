from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse

# ===============================================
# ==================Mes ajouts ==================
# ===============================================
from pwn import *
import json
import string

r = remote('socket.cryptohack.org', 13375, level = 'info')

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

ALICE_N = 22266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577
ALICE_E = 3 # low exponent


# ===============================================
# ===============================================
# ===============================================

FLAG = "crypto{????????????????????}"


class Challenge():
    def __init__(self):
        self.before_input = "Place your vote. Pedro offers a reward to anyone who votes for him!\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'vote':
            vote = int(your_input['vote'], 16)
            verified_vote = long_to_bytes(pow(vote, ALICE_E, ALICE_N))

            vote = verified_vote.split(b'\00')[-1]

            if vote == b'VOTE FOR PEDRO':
                return {"flag": FLAG}
            else:
                return {"error": "You should have voted for Pedro"}

        else:
            return {"error": "Invalid option"}

def find_cube_root_hensel(target_binary_int, bits):
    """
    Trouve x tel que x^3 = target_binary_int (mod 2^bits)
    L'entier target_binary_int doit être impair.

    A etudier le lifting de Hensel pour mieux comprendre
    """
    if target_binary_int % 2 == 0:
        return "Erreur : Le nombre doit être impair pour garantir une solution via Hensel."

    # Solution de base : x^3 = a (mod 2^1) -> x = 1
    x = 1
    
    # On remonte de n = 1 jusqu'à 'bits'
    for n in range(1, bits):
        # On regarde si la solution actuelle satisfait l'étape suivante (mod 2^(n+1))
        # Si (x^3 - a) n'est pas divisible par 2^(n+1), on doit corriger x.
        if (pow(x, 3) - target_binary_int) % (2**(n + 1)) != 0:
            # Correction : on ajoute 2^n à x
            x += 2**n
            
    return x

def recover(interface):

    signature = bin(bytes_to_long(b'VOTE FOR PEDRO')+(2**120)*1)
    a = int(signature,2) # Conversion en entier (45 en décimal)
    n_bits = len(signature)

    vote = find_cube_root_hensel(a, n_bits)
    res = interface({'option':'vote', "vote":hex(vote)})["flag"]
    return res


if __name__ == "__main__":
    # ===== local =====
    challenge = Challenge()
    interface_ = challenge.challenge

    flag = recover(interface_)
    assert flag == FLAG

    # ===== cryptohack =====
    r.readline()
    interface_ = interface

    flag = recover(interface_)
    assert flag == "crypto{y0ur_v0t3_i5_my_v0t3}"