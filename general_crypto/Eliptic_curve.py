import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tonellishanks import tonellishanks  


class ElipticCurve():
    def __init__(self,p):
        self.p=p

    def __str__(self):
        pass

    def __eq__(self):
        pass

    def __repr__(self):
        return self.__str__()

class Montgomery(ElipticCurve):
    def __init__(self, B, A, p):
        super().__init__(p=p)
        self.B=B
        self.A=A

        # Tester l'histoire du carré de A ?
    
    def __str__(self):
        return f"{self.B}y^2 = x^3 + {self.A}x^2 + x mod({self.p})"

    def __eq__(self, other):
        return (self.A, self.B, self.p) == (other.A, other.B, other.p)

    def testPoint(self, P):
        return (self.B*P.y**2-P.x**3 - self.A * P.x**2 - P.x)%self.p == 0
    
    def y_square(self, x):
        return (x**3 + self.A * x**2 + x)%self.p

    def point_from_x(self, x):
        #pas très optimisé mais bref
        integer=self.y_square(x)
        y = tonellishanks(integer, self.p)
        return PointMontgomery(self, x, y)

class WeierStrass(ElipticCurve):
    def __init__(self, a, b, p, secure=True):
        # Forme de Weirstrass
        super().__init__(p=p)
        self.a = a
        self.b = b
        self.secure=secure

        self.discriminant = -16 * (4 * a**3 + 27 * b**2) %p

        if self.isSingular() and self.secure:
            # we aren't ttesting is the curse is anomalous btw
            raise Exception("The curve is singular")
    
    def __str__(self):
        return f"y^2 = x^3 + {self.a}x + {self.b} mod({self.p})"

    def __eq__(self, other):
        return (self.a, self.b, self.p) == (other.a, other.b, other.p)

    def isSingular(self):
        return self.discriminant == 0

    def testPoint(self, P):
        return P.infinity or (P.y**2-P.x**3 - self.a * P.x - self.b)%self.p == 0
    
    def y_square(self, x):
        return (x**3 + self.a * x + self.b)%self.p

    def point_from_x(self, x):
        #pas très optimisé mais bref
        integer=self.y_square(x)
        y = tonellishanks(integer, self.p)
        if y is None and self.secure:
            raise Exception("Point not on the Curve")

        # on va calculer y et -y et prendre la plus grande coordonénée y 
        return PointWeirstrass(self,x,y)

class Point:
    def __init__(self,curve,x=None,y=None):
        pass

    def __eq__(self, other):
        if self.curve==other.curve:
            if self.infinity and other.infinity: 
                #les deux sont des points à l'infini
                return True
            elif not self.infinity and not other.infinity: 
                #les deux ne sont pas des points à l'infini
                return (self.x, self.y) == (other.x, other.y)
            else: 
                #l'un des deux est le point à l'infini
                return False
        else: # les deux courbes ne sont pas les mêmes
            return False

    def __str__(self):
        if self.infinity:
            return f"Infinity"
        else:
            return f"({self.x},{self.y})"

    def __repr__(self):
        return self.__str__()

    def __add__(self,other):
        pass

    def __sub__(self,other):
        return self.__add__(-other)

class PointWeirstrass(Point):
    def __init__(self,curve,x=None,y=None, secure=True):
        super().__init__(curve,x=None,y=None)

        if isinstance(curve,WeierStrass):
            self.curve=curve
        else:
            raise Exception("The curve is not of WeierStrass")

        self.secure=secure

        if x is None and y is None:
            self.infinity=True
        else:
            if not isinstance(x, int) or not isinstance(y, int):
                raise Exception(f"x,y should be of int type and not {type(x)},{type(y)}")
            self.x=x%self.curve.p
            self.y=y%self.curve.p
            self.infinity=False
        

        if self.secure and not self.oncurve() :
            raise Exception("The Point is not on the curve")
    
    def __neg__(self):
        if self.infinity:
            return self
        else:
            return PointWeirstrass(self.curve, self.x, (-1*self.y)%self.curve.p, secure=self.secure)

    def __add__(self,other):

        if self.secure and (self.curve != other.curve):
            raise Exception("The points are defined on different curves")
        
        if self.infinity:
            return other

        elif other.infinity:
            return self

        elif self==-other: #P==-Q
            return PointWeirstrass(self.curve, secure=self.secure) #on retourne le point à l'infini

        else:
            if self!=other: # si P!=Q
                lambda_=(other.y-self.y)*pow(other.x-self.x, -1, self.curve.p)
            else: # si P==Q Point doubling
                 lambda_=(3*self.x**2+self.curve.a)*pow(2*self.y, -1, self.curve.p)

            x3=(lambda_**2-self.x-other.x)%self.curve.p
            y3=(lambda_*(self.x-x3)-self.y)%self.curve.p

            return PointWeirstrass(self.curve, x3, y3, secure=self.secure)
    
    def __mul__(self, k):

        result = PointWeirstrass(self.curve, secure=self.secure)
        PointToAdd = self

        # ========== This is UNSECURE to side channels by design ==========
        
        while k > 0: # ici on fait LSB first 
            if k & 1: # on test si le LSB est 1
                #si c'est 1 on ajoute
                result = result + PointToAdd
            PointToAdd = PointToAdd + PointToAdd   
            k >>= 1 # bit shifting vers la droite

        return result

    def oncurve(self):
        return self.curve.testPoint(self)

class PointMontgomery(Point):
    def __init__(self,curve,x,y):
        super().__init__(curve,x,y)

        if isinstance(curve,Montgomery):
            self.curve=curve
        else:
            raise Exception("The curve is not of Montgomery")

        self.infinity=False
        self.x=x%self.curve.p
        self.y=y%self.curve.p

        if not self.curve.testPoint(self):
            raise Exception("The Point is not on the curve")

    def __neg__(self):
        return PointMontgomery(self.curve, self.x, (-1*self.y)%self.curve.p)
    
    def __add__(self,other):

        if (self.curve != other.curve):
            raise Exception("The points are defined on different curves")
    
        if self!=other: 
            # si P!=Q
            alpha=(other.y-self.y)*pow(other.x-self.x, -1, self.curve.p)%self.curve.p
            x3=(self.curve.B*alpha**2-self.curve.A-self.x-other.x)%self.curve.p
            y3=(alpha*(self.x-x3)-self.y)%self.curve.p

        else: 
            # si P==Q Point doubling
            alpha=(3*self.x**2+2*self.curve.A*self.x+1)*pow(2*self.curve.B*self.y, -1, self.curve.p)%self.curve.p
            x3=(self.curve.B*alpha**2-self.curve.A-2*self.x)%self.curve.p
            y3=(alpha*(self.x-x3)-self.y)%self.curve.p

        return PointMontgomery(self.curve, x3, y3)

    def __rmul__(self, k):

        R0 = self
        R1 = self + self

        #On doit renverser la decomposition binaire
        k_binary_decomposition=[int(k) for k in list(bin(k))[2:]][::-1]
        n=len(k_binary_decomposition)

        #Implementation du Montgommery Ladder
        for k in range(n-2,-1,-1): # n-2 => 0
            if k_binary_decomposition[k]==0:
                R1=R0+R1
                R0=R0+R0
            else:
                R0=R0+R1
                R1=R1+R1
        return R0


class ECDH:
    def __init__(self):
        pass

    def share_point_from_point(secret,public_key_point):
        return secret*public_key_point

    def shared_secret_sha1(secret,public_key):
        shared_secret_point=ECDH.share_point_from_point(secret,public_key)

        sha1_hash = hashlib.sha1()
        sha1_hash.update(str(shared_secret_point.x).encode())
        return sha1_hash.hexdigest()

    def is_pkcs7_padded(message):
        padding = message[-message[-1]:]
        return all(padding[i] == len(padding) for i in range(0, len(padding)))

    def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
        # Derive AES key from shared secret
        sha1 = hashlib.sha1()
        sha1.update(str(shared_secret).encode('ascii'))
        key = sha1.digest()[:16]
        # Decrypt flag
        ciphertext = bytes.fromhex(ciphertext)
        iv = bytes.fromhex(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        if ECDH.is_pkcs7_padded(plaintext):
            return unpad(plaintext, 16).decode('ascii')
        else:
            return plaintext.decode('ascii')



if __name__ == "__main__":
    curve1=WeierStrass(497, 1768, 9739)
    G=PointWeirstrass(curve1,1804,5368)

    # ========== Point Inverse & Infinity ===========
    
    P=PointWeirstrass(curve1, 8045,6936)
    Q=-P
    Z=P+Q
    assert Q==PointWeirstrass(curve1, 8045,2803)
    assert Z==PointWeirstrass(curve1) # point at infinity
    assert P-P==PointWeirstrass(curve1) # point substraction
    del P, Q, Z

    # =========== Point Addition ===========
    
    X=PointWeirstrass(curve1, 5274,2841)
    Y=PointWeirstrass(curve1, 8669,740)

    assert X+Y==PointWeirstrass(curve1, 1024,4440)
    assert X+X==PointWeirstrass(curve1, 7284,2107)

    P=PointWeirstrass(curve1, 493,5564)
    Q=PointWeirstrass(curve1, 1539,4742)
    R=PointWeirstrass(curve1, 4403,5202)

    S=P+P+Q+R
    assert S==PointWeirstrass(curve1, 4215,2162)
    del X,Y,P,Q,R,S

    # ========== Scalar Multiplication ===========
    
    X=PointWeirstrass(curve1, 5323,5438)
    assert 1337*X==PointWeirstrass(curve1,1089,6931)

    P=PointWeirstrass(curve1, 2339,2213)
    Q=7863*P
    assert Q==PointWeirstrass(curve1,9467,2742)
    del X,P,Q

    
    # =========== Shared Secret from Public Point ============
    
    #Alice Public Key
    AliceKey=PointWeirstrass(curve1, 815,3190)
    secret=1829 #secret key
    shared_secret_sha1=ECDH.shared_secret_sha1(secret, AliceKey)
    assert shared_secret_sha1=="80e5212754a824d3a4aed185ace4f9cac0f908bf"
    del AliceKey, secret, shared_secret_sha1

    # =========== Shared Secret from Public x Coordinate ===============
    
    x=4726
    secret=6534
    AliceKey=curve1.point_from_x(x)

    shared_point=ECDH.share_point_from_point(secret, AliceKey)
    iv = "cd9da9f1c60925922377ea952afc212c"
    ciphertext = "febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8"

    assert ECDH.decrypt_flag(shared_point.x, iv, ciphertext)=='crypto{3ff1c1ent_k3y_3xch4ng3}'
    del x, secret, AliceKey, shared_point, iv, ciphertext

    # =========== Shared Secret from Public x Coordinate ===============
    curve2=Montgomery(1, 486662, (2**255)-19)
    x=9
    G=curve2.point_from_x(x)
    Q=21130179955454*G

    assert Q.x==49231350462786016064336756977412654793383964726771892982507420921563002378152
    del x, G, Q