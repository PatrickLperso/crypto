#!/usr/bin/env python3
import socket
import json
import math
import time
import sys
from scipy.special import softmax
from functools import reduce

# Connection info
HOST = "socket.cryptohack.org"
PORT = 13423

# tuning
LIMIT = 375 # queries per byte
CONF = 0.99975 
L_YES = math.log(0.4 / 0.6)
L_NO = math.log(0.6 / 0.4)

def xor(*args):
    return bytes([reduce(lambda x, y: x ^ y, t) for t in zip(*args)])

class Remote:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((HOST, PORT))
        self.recv() # skip banner

    def recv(self):
        buf = b''
        while not buf.endswith(b'\n'):
            buf += self.s.recv(1)
        return buf

    def send(self, data):
        self.s.sendall(json.dumps(data).encode() + b'\n')
        return json.loads(self.recv().decode())

    def close(self):
        self.s.close()

def solve():
    while True:
        try:
            r = Remote()
            break
        except:
            time.sleep(1)

    # get initial ct
    resp = r.send({"option": "encrypt"})
    if "ct" not in resp: return
    
    full_ct = bytes.fromhex(resp["ct"])
    iv = full_ct[:16]
    ct = full_ct[16:]
    pt = b""
    
    reqs = 0
    print(f"[*] Attacking {len(ct)} bytes...")

    # process blocks
    for b_idx in range(0, len(ct), 16):
        block_dec = b""
        block_ct = ct[b_idx:b_idx+16]
        prev = (iv + ct)[b_idx:b_idx+16]

        for i in range(1, 17):
            global_idx = b_idx + (i - 1)
            budget = (global_idx + 1) * LIMIT
            
            # 1. filter valid hex padding
            cands = []
            for b in range(256):
                attempt = bytes([b])
                # verify hex char constraint
                check = xor(attempt, bytes([i]), bytes([prev[16-i]]))
                if check in b'0123456789abcdef':
                    payload = bytes([0]*(16-i)) + attempt + block_dec + block_ct
                    cands.append({
                        "b": attempt.hex(),
                        "ct": payload.hex(),
                        "score": 0,
                        "p": 1.0/16
                    })

            # 2. initial baseline (5 rounds)
            for _ in range(5):
                for c in cands:
                    res = r.send({"option": "unpad", "ct": c["ct"]})["result"]
                    reqs += 1
                    c["score"] += L_YES if res else L_NO

            # 3. refine until confident
            iter_count = 0
            while True:
                # update probs
                scores = [x["score"] for x in cands]
                probs = softmax(scores)
                for k, p in enumerate(probs): cands[k]["p"] = p
                
                cands.sort(key=lambda x: x["p"], reverse=True)
                top = cands[0]

                if top["p"] > CONF or reqs > budget:
                    break
                
                # hard stop
                if reqs > 11990: break

                # query top 2 (sometimes)
                targets = [cands[0]]
                if iter_count % 3 == 0 and len(cands) > 1:
                    targets.append(cands[1])

                for t in targets:
                    res = r.send({"option": "unpad", "ct": t["ct"]})["result"]
                    reqs += 1
                    t["score"] += L_YES if res else L_NO
                
                iter_count += 1

            if reqs >= 12000:
                print("\n[-] Budget blown.")
                r.close()
                return

            # reconstruct byte
            winner = bytes.fromhex(cands[0]["b"])
            if i != 16:
                # adjust padding for next byte
                block_dec = xor(winner + block_dec, bytes([i]*i), bytes([i+1]*i))
            else:
                block_dec = winner + block_dec

            print(f"\rByte {global_idx+1}/32 | Reqs: {reqs} | Conf: {cands[0]['p']:.4f}", end="")

        # Block finished
        dec = xor(block_dec, bytes([0x10]*16))
        if b_idx == 0:
            pt += xor(dec, iv)
        else:
            pt += xor(dec, ct[b_idx-16:b_idx])
        
    print("\n")
    try:
        final = pt.decode()
        print(f"[+] PT: {final}")
        print(r.send({"option": "check", "message": final}))
    except:
        print(f"[-] Decode error: {pt}")
    
    r.close()

if __name__ == "__main__":
    while True:
        try:
            solve()
            break
        except:
            continue