from pwn import *
import json
import codecs
import base64
 
import Crypto
from Crypto.Util.number import *

r = remote('socket.cryptohack.org', 13382, level = 'debug')

def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    response=r.sendline(request)
    return response
    
if __name__ == "__main__":
    request = {
                    'private_key':Crypto.Util.number.bytes_to_long(bytes.fromhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))+1,
                    'host':"www.bing.com",
                    'curve':"secp256r1",    
                    'generator':[0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A]
    }

    print(r.readline())

    response=json_send(request)
    print(response)

    print(r.readline())
