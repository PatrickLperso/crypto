from Modular_arithmetic import pgcd, inverse_modulaire 
from hashlib import sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2

class Rsa_privatekey():
    def __init__(self, p, q, e=65537, secure=True):
        # ============ This is unsecure ================
        # ============ Don't use it, it's textbook RSA ================
        
        # à faire tester si p & q sont des nombres premiers 
        # Mettre en place des protections contre les attaques habituelles de factorisation 
        # pareil sur e 
        # padding implementation
        # CRT for more efficient squaring

        self.secure=secure
        self.N = p*q
        self.phi = (p-1)*(q-1)

        if self.secure and e!=65537:
            raise Exception("e is to small")
        else:
            self.e=e

        self.d = self.decryption_key()
        self.public_key = self.gen_publickey()
        
    def decryption_key(self):
        if pgcd(self.e, self.phi)==1:
            return inverse_modulaire(self.e, self.phi)
        else:
            raise Exception("e is not inversible mod phi N")
    
    def gen_publickey(self):
        return Rsa_publickey(self.N, self.e)
    
    def decrypt(self, cipher:int):
        return pow(bytes_to_long(bytes.fromhex(cipher)), self.d, self.N)

    def sign(self, message:str):
        try:
            digest = bytes_to_long(sha256(message.encode()).digest())
            return long_to_bytes(pow(digest, self.d, self.N)).hex()
        except:
            raise Exception("Something went wrong")


class Rsa_publickey():
    def __init__(self, N, e):
        self.N=N
        self.e = e
    
    def encrypt(self, message:int):
        return long_to_bytes(pow(message, self.e, self.N)).hex()
    
    def verify_sign(self, message:str, signature:str):
        try:
            digest = sha256(message.encode()).digest().hex()
            return long_to_bytes(pow(bytes_to_long(bytes.fromhex(signature)), self.e, self.N)).hex() == digest
        except:
            return False

if __name__ == "__main__":
    rsa_private = Rsa_privatekey(p=857504083339712752489993810777, q=1029224947942998075080348647219, e=65537)
    rsa_public = rsa_private.public_key

    # ========== test encryption ==========
    message = 13371337

    cipher = rsa_public.encrypt(message)
    assert cipher == "0c5bea8238c2fc7a2ce3c139445b21c2a46eb17bebbbd4eafc"

    # ========== test decryption ==========
    assert message == rsa_private.decrypt(cipher)
    del rsa_private, rsa_public, message, cipher


    # ========== test signature ==========
    p=11990777820067100994780414270167522365392358756633286594387838516747381628112285047569945138832347125147781887173543938009440629146114586911600216924443587
    q=10552597795282489389769613260320838835232645052506657458761747039369334291838430330649485490416764890138885861153938455155832921673994667274261696942924021
    rsa_private = Rsa_privatekey(p=p, q=q, e=65537)
    rsa_public = rsa_private.public_key

    message_to_sign = "crypto{Immut4ble_m3ssag1ng}"
    message_signature = rsa_private.sign(message_to_sign)

    assert message_signature == 'a7a627bd368d8d41fa98c558847737d0eb65d3b339074c4b97d2139d16dbdcf26ba0c76839c53ed146de010f7f4c26910a87fab52fddb2704b3451a695ebcd2b457bf881202ebd9d1478fc6449f4e8647d4195824f44dcbe9fe1488e17ae9f39368cdb395e0d4cbf842dccd22a4e49ddd1cdf026ca9a3804a577066b3fb85135'
    assert rsa_public.verify_sign(message_to_sign, message_signature)

    # ========== test false signature ==========
    false_signature = 'a7a627b9368d8d41fa98c558847737d0eb65d3b339074c4b97d2139d16dbdcf26ba0c76839c53ed146de010f7f4c26910a87fab52fddb2704b3451a695ebcd2b457bf881202ebd9d1478fc6449f4e8647d4195824f44dcbe9fe1488e17ae9f39368cdb395e0d4cbf842dccd22a4e49ddd1cdf026ca9a3804a577066b3fb85135'
    assert false_signature!=message_signature

    assert not rsa_public.verify_sign(message_to_sign, false_signature)

    # =========== small exponent attack ============
    e=7
    rsa_private = Rsa_privatekey(p=p, q=q, e=e, secure=False)
    rsa_public = rsa_private.public_key
    
    message = b'hello'
    assert message == long_to_bytes(int(gmpy2.iroot(bytes_to_long(bytes.fromhex(rsa_public.encrypt(bytes_to_long(message)))),e)[0]))

    # ============= one prime is not secure at all =========
    n = 171731371218065444125482536302245915415603318380280392385291836472299752747934607246477508507827284075763910264995326010251268493630501989810855418416643352631102434317900028697993224868629935657273062472544675693365930943308086634291936846505861203914449338007760990051788980485462592823446469606824421932591
    e = 65537   
    ct = 161367550346730604451454756189028938964941280347662098798775466019463375610700074840105776873791605070092554650190486030367121011578171525759600774739890458414593857709994072516290998135846956596662071379067305011746842247628316996977338024343628757374524136260758515864509435302781735938531030576289086798942
    d =  inverse_modulaire(e, n-1)
    decrypt = long_to_bytes(pow(ct, d,n))
    assert decrypt == b'crypto{0n3_pr1m3_41n7_pr1m3_l0l}'

    # ============= small exponent Salty =========
    n = 110581795715958566206600392161360212579669637391437097703685154237017351570464767725324182051199901920318211290404777259728923614917211291562555864753005179326101890427669819834642007924406862482343614488768256951616086287044725034412802176312273081322195866046098595306261781788276570920467840172004530873767                                                                  
    e = 1
    ct = 44981230718212183604274785925793145442655465025264554046028251311164494127485

    assert b'crypto{saltstack_fell_for_this!}' == long_to_bytes(44981230718212183604274785925793145442655465025264554046028251311164494127485)

    # =========== Modulus inutilus ============
    n = 17258212916191948536348548470938004244269544560039009244721959293554822498047075403658429865201816363311805874117705688359853941515579440852166618074161313773416434156467811969628473425365608002907061241714688204565170146117869742910273064909154666642642308154422770994836108669814632309362483307560217924183202838588431342622551598499747369771295105890359290073146330677383341121242366368309126850094371525078749496850520075015636716490087482193603562501577348571256210991732071282478547626856068209192987351212490642903450263288650415552403935705444809043563866466823492258216747445926536608548665086042098252335883
    e = 3
    ct = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957   
    
    assert b'crypto{N33d_m04R_p4dd1ng}' == long_to_bytes(int(gmpy2.iroot(ct,e)[0]))