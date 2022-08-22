import math
import numpy as np
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
                        # Elliptic Curves implementation #
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

class ell_curve(object):
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b
        self.discriminant = -16*(4*a**3+27*b**2)
    #    if not self.isSmooth():
    #        raise Exception(&quot;The curve %s is not smooth!&quot; % self)

    def testPoint(self, P):
      return pow(P.y,2,self.p) == ( pow(P.x,3,self.p) + self.a * P.x + self.b ) % self.p

    def isSmooth(self):
        return self.discriminant != 0


class point(object):
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
# function to add points on the curve
    def __add__(self,Q):
        if not( self.curve.testPoint(self) and self.curve.testPoint(Q) ):
            raise Exception("Points outside curve!")
        if isinstance(Q,ideal):
            return P
        else:
            x_1, y_1, x_2, y_2 = self.x, self.y, Q.x, Q.y
            if (x_1 - x_2) % self.curve.p == 0 and (y_1 + y_2) % self.curve.p == 0:
                return ideal(curve)
            else:
                if (x_1 - x_2) % self.curve.p == 0 and (y_1 - y_2) % self.curve.p == 0:
                    lamb = ((3*pow(x_1,2,self.curve.p) + self.curve.a)*pow(2*y_1,-1,self.curve.p))%self.curve.p
                else:
                    lamb = ( (y_2-y_1)*pow(x_2-x_1,-1,self.curve.p) ) % self.curve.p
                x_3 = (lamb**2 - x_1 - x_2) % self.curve.p
                y_3 = (lamb*(x_1-x_3)-y_1) % self.curve.p
                return point(self.curve,x_3,y_3)

    def __neg__(self):
        return point(self.curve, self.x, -self.y)

    def __mul__(self,n):
        if not isinstance(n, int):
            raise Exception("Scalar factor is not an integer!")
        if n == 0:
            return ideal(self.curve)
        else:
            Q, R = self, ideal(self.curve)
            while n > 0:
                if n % 2 == 1:
                    R = R + Q
                Q = Q + Q
                n = int(n/2)
            return R

    def __rmul__(self, n):
        return self * n


class ideal(point):
    def __init__(self, curve):
        self.curve = curve

    def __add__(self, Q):
        return Q

    def __neg__(self):
        return self

    def __mul__(self,n):
        if not isinstance(n, int):
            raise Exception("Scalar factor is not an integer!")
        return self

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

curv = ell_curve(9739,497, 1768)
G = point(curv, 1804,5368)

x = 4726
y = pow( pow(x,3,9739)+497*x+1768, 9740//4, 9739)

P = point(curv,x,y)

print(curv.testPoint(P))

Q_a = point(curv, x, y)
n_b = 6534


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

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


shared_secret = (n_b*Q_a).x
iv = 'cd9da9f1c60925922377ea952afc212c'
ciphertext = 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'

print(decrypt_flag(shared_secret, iv, ciphertext))
