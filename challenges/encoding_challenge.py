from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64
import codecs

from pwn import *
import json

r = remote('socket.cryptohack.org', 13377, level = 'info')

from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64
import codecs
import random

FLAG = "crypto{????????????????????}"
ENCODINGS = [
    "base64",
    "hex",
    "rot13",
    "bigint",
    "utf-8",
]
with open('/usr/share/dict/words') as f:
    WORDS = [line.strip().replace("'", "") for line in f.readlines()]


class Challenge():
    def __init__(self):
        self.no_prompt = True # Immediately send data from the server without waiting for user input
        self.challenge_words = ""
        self.stage = 0

    def create_level(self):
        self.stage += 1
        self.challenge_words = "_".join(random.choices(WORDS, k=3))
        encoding = random.choice(ENCODINGS)

        if encoding == "base64":
            encoded = base64.b64encode(self.challenge_words.encode()).decode() # wow so encode
        elif encoding == "hex":
            encoded = self.challenge_words.encode().hex()
        elif encoding == "rot13":
            encoded = codecs.encode(self.challenge_words, 'rot_13')
        elif encoding == "bigint":
            encoded = hex(bytes_to_long(self.challenge_words.encode()))
        elif encoding == "utf-8":
            encoded = [ord(b) for b in self.challenge_words]

        return {"type": encoding, "encoded": encoded}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if self.stage == 0:
            return self.create_level()
        elif self.stage == 100:
            self.exit = True
            return {"flag": FLAG}

        if self.challenge_words == your_input["decoded"]:
            print(self.challenge_words, your_input["decoded"])
            return self.create_level()

        raise Exception("bad shit")
        return {"error": "Decoding fail"}


def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


def decode_challenge(input_to_decode):
    type_ = input_to_decode["type"]
    encoded_ = input_to_decode["encoded"]
    
    if type_ == "base64":
        res = base64.b64decode(encoded_.encode()).decode()
    elif type_ == "hex":
        res =  bytes.fromhex(encoded_).decode()
    elif type_ == "rot13":
        res =  codecs.decode(encoded_, 'rot_13')
    elif type_ == "bigint":
        res = long_to_bytes(int(encoded_,16)).decode()
    else:
        res =  "".join([chr(k) for k in encoded_])

    return {"decoded" : res}

    
if __name__ == "__main__":

    interface = interface_request
    
    while True:
        received = json_recv()
        if "flag" in received:
            print("FLAG: %s" % received["flag"])
            sys.exit(0)
        input_decoded = decode_challenge(received)
        json_send(input_decoded)