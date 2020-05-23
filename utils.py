from Crypto.Hash import BLAKE2b, HMAC, SHA256
from sage.all import Integers, GF, EllipticCurve, Integer

from Crypto.Cipher import AES
qq = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Fq = Integers(qq)

def pad(x, y):
    # on enlève 0b de la string
    x = x[2:]
    y = y[2:]

    diff_x = 256 - len(x)
    diff_y = 256 - len(y)

    return ('0' * diff_x) + x, ('0' * diff_y) + y

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def is_point_on_G(point):
    # On vérifie que alpha n'est pas le point à l'infinie et que q*alpha soit le point à l'infinie
    if point.is_zero() and not (qq * point).is_zero():
        return False
    return True

