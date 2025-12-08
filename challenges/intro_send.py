#!/usr/bin/env python3

from pwn import * # pip install pwntools
import json

HOST = "socket.cryptohack.org"
PORT = 13382

r = remote(HOST, PORT)


def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

if __name__ == "__main__":
    print(r.readline())

    request = {
        "buy": "flag"
    }
    json_send(request)

    response = json_recv()

    print(response)
