import os, sys
from Crypto.PublicKey import RSA

if __name__ == "__main__":
    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")

    with open(os.path.join(folder, 'privacy_enhanced_mail.pem'), "rb") as f:
        data = f.read()
        mykey = RSA.import_key(data)
    print(mykey.d)

