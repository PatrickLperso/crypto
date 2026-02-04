import random
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
import os
from pwn import *
import math 

FLAG = b"crypto{ouep}"

r = remote('archive.cryptohack.org', 11840, level = 'debug')

# w,y for the relation `g^w = y mod p` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,p)

def correctness_client(p, q, g, w0,y0,y1):
    # of cours this is dumb unsecure because
    # i'm always selecting the bsame circuit always
    print(r.readline())
    print(r.readline())

    e1 = random.randint(0,2**511-1)
    
    # malicious a1
    z1 = random.randint(0,q)
    a1 = pow(g, z1, p)*pow(y1, -e1, p)


    # honest a0
    r0 = random.randint(0,q)
    a0 = pow(g, r0, p)

    assert (a0%p) >= 1 and (a1%p) >= 1
    assert pow(a0, q, p) == 1 and pow(a1, q, p) == 1

    # send (a0,a1) and get s
    r.sendline(str(a0))
    r.sendline(str(a1))

    s = int(r.readline().decode().strip("\n").split(" = ")[1])

    # Compute honest valid transcript
    e0 = s ^ e1
    z0 = (r0+w0*e0)%q

    assert e0^e1 == s
    assert pow(g,z0,p) == (a0*pow(y0,e0,p)) % p
    assert pow(g,z1,p) == (a1*pow(y1,e1,p)) % p

    # send transcripts
    r.sendline(str(e0))
    r.sendline(str(e1))
    r.sendline(str(z0))
    r.sendline(str(z1))

def special_soundness(p, q, g):
    print(r.readline())
    
    y0 = int(r.readline().decode().strip("\n").split(" = ")[1])
    y1 = int(r.readline().decode().strip("\n").split(" = ")[1])

    print(r.readline())
    print(r.readline())

    a0_1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    a1_1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    s_1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    e0_1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    e1_1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    z0_1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    z1_1 = int(r.readline().decode().strip("\n").split(" = ")[1])

    print(r.readline())
    a0_2 = int(r.readline().decode().strip("\n").split(" = ")[1])
    a1_2 = int(r.readline().decode().strip("\n").split(" = ")[1])
    s_2 = int(r.readline().decode().strip("\n").split(" = ")[1])
    e0_2 = int(r.readline().decode().strip("\n").split(" = ")[1])
    e1_2 = int(r.readline().decode().strip("\n").split(" = ")[1])
    z0_2 = int(r.readline().decode().strip("\n").split(" = ")[1])
    z1_2 = int(r.readline().decode().strip("\n").split(" = ")[1])

    # on met les transcripts obtenus en forme
    t0s = [[a0_1,e0_1,z0_1], [a1_1,e1_1,z1_1]]
    t1s = [[a0_2,e0_2,z0_2], [a1_2,e1_2,z1_2]]

    # on teste les solutions possibles en itérant de transcripts en transcripts
    for t0 in t0s:
        for t1 in t1s:
            if math.gcd(t0[1]-t1[1], q)==1:
                w_try = ((t0[2]-t1[2])*pow(t0[1]-t1[1],-1, q))%q
                if pow(g, w_try,p)==y0 or pow(g, w_try,p)==y1:
                    r.sendline(str(w_try))
                    print(r.readline())
                    return
            else:
                continue

def shvk(p, q, g):

    print(r.readline())

    y0 = int(r.readline().decode().strip("\n").split(" = ")[1])
    y1 = int(r.readline().decode().strip("\n").split(" = ")[1])
    s = int(r.readline().decode().strip("\n").split(" = ")[1])

    #  ==== craft malicious transcirpt ==========
    z0 = random.randint(0,q)
    e0 = random.randint(0,2**511)
    a0 = pow(g, z0, p)*pow(y0, -e0, p)

    #  ==== craft second malicious transcript with imposed e1 ==========
    z1 = random.randint(0,q)
    e1 = e0 ^ s
    a1 = pow(g, z1, p)*pow(y1, -e1, p)
    
    assert e0^e1 == s
    assert pow(g,z0,p) == (a0*pow(y0,e0,p))%p
    assert pow(g,z1,p) == (a1*pow(y1,e1,p))%p
    
    r.sendline(str(a0))
    r.sendline(str(a1))
    r.sendline(str(e0))
    r.sendline(str(e1))
    r.sendline(str(z0))
    r.sendline(str(z1))

    r.readline()

def SHVZK():
    print(f'Finally, show me you can simulate proofs!')

    # w,y for the relation `g^w = y mod p` we want to prove knowledge of
    w0 = random.randint(0,q)
    y0 = pow(g,w0,p)
    w1 = random.randint(0,q)
    y1 = pow(g,w1,p)
    assert (y0%p) >= 1 and (y1%p) >= 1
    assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1


    s = random.randint(0,2**511-1)
    print(f'y0 = {y0}')
    print(f'y1 = {y1}')
    print(f'give me satisfying transcript for s = {s}')

    a0 = int(input(f'a0: '))
    a1 = int(input(f'a1: '))
    e0 = int(input(f'e0: '))
    e1 = int(input(f'e1: '))
    z0 = int(input(f'z0: '))
    z1 = int(input(f'z1: '))

    # Verifier checks e0 xor e1 == s mod p
    if not e0^e1 == s:
        print("something went wrong with e0^e1 == s")
        exit()
    # Verifier checks g^w0 = A0*h^e0 mod p
    if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:
        print("something went wrong with b=0")
        exit()
        # Verifier checks g^z1 = A1*h^e1 mod p
    if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
        print("something went wrong with verifying b=1 :(")
        exit()

if __name__ == "__main__":

    # Diffie-Hellman group (512 bits)
    # p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
    p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
    q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
    g = 2

    w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
    y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
    # w1 = REDACTED
    y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617

    ### Correctness!
    # prove to the server you know either w0 or w1
    correctness_client(p, q, g, w0,y0,y1)

    ### Now do special soundness!!! 
    # The server will compute two satisfying transcripts, extract one of the witnesses :)
    special_soundness(p, q, g)

    ### SHVZK
    # Finally, show me you can simulate proofs!
    shvk(p, q, g)

    flag = r.readline()
    assert flag.decode().split("'")[1] == 'crypto{sigma_protocols_compose!}'
