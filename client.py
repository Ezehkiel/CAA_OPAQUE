from Crypto.Protocol.KDF import scrypt
from sage.all import Integers, GF, EllipticCurve, Integer
import socket
from Crypto.Hash import BLAKE2b, HMAC, SHA256
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex



PWD = "password"
SSID = "YWM0MjEwYzkxNzll"

# tow = 128
# secp256r1
# https://kel.bz/post/sage-p256/
# Finite field prime
p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# Curve parameters for the curve equation: y^2 = x^3 + a256*x +b256
a256 = p256 - 3
b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

qq = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Base point (x, y)
gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Create a finite field of order p256
FF = GF(p256)

Fq = Integers(qq)
# Define a curve over that field with specified Weierstrass a and b parameters
EC = EllipticCurve(FF, [a256, b256])
EC.set_order(qq)

g = EC(FF(gx), FF(gy))

r = Fq.random_element()
x_u = Fq.random_element()

X_u = x_u.lift() * g

from server import qq, EC, FF


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


def new_point_from_coord(string):
    return EC(FF(string.split(',')[0]), FF(string.split(',')[1]))


def compute_alpha(password):
    blk2 = BLAKE2b.new(digest_bits=256)

    blk2.update(PWD.encode())
    return (r * Integer("0x" + blk2.hexdigest())).lift() * g


def get_beta_X_s_c_A_s(payload):
    values = payload.split("$")
    beta_points = values[0].split(",")
    X_s_points = values[1].split(",")
    c = values[2]
    A_s = values[3]

    try:
        beta = EC(FF(beta_points[0]), FF(beta_points[1]))
        X_s = EC(FF(X_s_points[0]), FF(X_s_points[1]))
        return beta, X_s, c, A_s
    except Exception as e:
        print("lejeu")
        print(str(e))
        raise


def compute_rw(_beta):
    beta_calc = _beta * (1 / r).lift()

    x, y = pad(bin(beta_calc[0]), bin(beta_calc[1]))
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    bytearray_password = bytearray(PWD.encode())

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_password + bytearray_x + bytearray_y)
    rw = blk2.digest()
    return rw


def decrypt_c(rw, c):
    values = c.split(",")
    data = values[0]
    mac = values[1]

    # KDF on calcule une fois avec 0 et une fois avec 1. Pour le sel la documentation
    # conseille quelque chose d'une longueur de 16bytes qui n'a pas besoin d'être secret
    # c'est pourquoi j'ai choisi de prendre le SSID car le client doit aussi connaitre le sel
    key_aes = scrypt('\x00'.encode() + rw, SSID, 32, N=2 ** 14, r=8, p=1)
    key_hmac = scrypt('\x01'.encode() + rw, SSID, 32, N=2 ** 14, r=8, p=1)

    h = HMAC.new(key_hmac, digestmod=SHA256)
    h.update(a2b_hex(data))
    try:
        h.hexverify(mac)
        cipher = AES.new(key_aes, AES.MODE_CTR, nonce=bytearray(1))
        plaintext = cipher.decrypt(a2b_hex(data))
        print("Plaintext: ", plaintext.decode())
        return plaintext.decode()
    except ValueError:
        print("perdu")
        raise


def parse_c(data):
    values = data.split(";")
    p_u = Integer(values[0])
    P_u = new_point_from_coord(values[1])
    P_s = new_point_from_coord(values[2])

    print("p_u", p_u)
    print("P_u", P_u)
    print("P_s", P_s)

    return p_u, P_u, P_s


def compute_ssid_prime(sid, ssid, alpha):
    # on va passer le sid et le ssid en binaire et on va padder jusqu'a 128, cela laisse des pareametre de 16 characters
    ssid_bin = ''.join('{0:08b}'.format(ord(x), 'b') for x in ssid)
    if len(ssid_bin) < 128:
        diff = 128 - len(ssid_bin)
        ssid_bin = '0' * diff + ssid_bin

    alpha_x = alpha[0]
    alpha_y = alpha[1]

    x, y = pad(bin(alpha_x), bin(alpha_y))
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))
    bytearray_ssid = bytearray(bitstring_to_bytes(ssid_bin))
    bytearray_sid = bytearray(sid.to_bytes(16, byteorder='big'))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_sid + bytearray_ssid + bytearray_x + bytearray_y)

    return blk2.digest()


def compute_e_u_or_e_s(point, prim):
    """
    Cette méthode va calculer e_u ou e_s
    :param point: X_u
    :param prim:  ssid'
    :return: e_u
    """
    point_x = point[0]
    point_y = point[1]

    # On fait en sorte que x et y soient sur 256 bit
    x, y = pad(bin(point_x), bin(point_y))

    # On transforme tout en bytearray
    bytearray_ssid_prime = bytearray(prim)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y + bytearray_ssid_prime)
    # On creer un Integer depuis notre hexa puis on fait modulo q
    return Fq(Integer('0x' + blk2.hexdigest()))


def compute_K(X_s, P_s, e_s, x_u, e_u, p_u):
    if not is_point_on_G(X_s) or not is_point_on_G(P_s):
        raise TypeError

    KE = ((P_s * e_s.lift()) + X_s) * (x_u + (e_u * p_u)).lift()
    x, y = pad(bin(KE[0]), bin(KE[1]))
    print("Ke point", KE)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y)
    return blk2.digest()


def compute_prf(value, prime, K):
    data = str(value) + b2a_hex(prime).decode()
    print("Data prf", data)
    h = HMAC.new(K, digestmod=SHA256)
    h.update(data.encode())
    return h.hexdigest()


soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(("127.0.0.1", 12346))

# p = input("Enter your password please\n")
alpha = compute_alpha(PWD)
payload = "{};{}".format("{},{}".format(str(X_u[0]), str(X_u[1])), "{},{}".format(str(alpha[0]), str(alpha[1])))

soc.send(payload.encode("utf8"))  # we must encode the string to bytes
result_bytes = soc.recv(4096)  # the number means how the response can be in bytes
result_string = result_bytes.decode("utf8")  # the return will be in bytes, so decode

try:
    beta, X_s, c, A_s = get_beta_X_s_c_A_s(result_string)
    rw = compute_rw(beta)
    plaintext = decrypt_c(rw, c)
    p_u, P_u, P_s = parse_c(plaintext)
    ssid_prime = compute_ssid_prime(1, SSID, alpha)
    # C alcul de e_u
    e_u = compute_e_u_or_e_s(X_u, ssid_prime)
    # Calcul de e_s
    e_s = compute_e_u_or_e_s(X_s, ssid_prime)
    K = compute_K(X_s, P_s, e_s, x_u, e_u, Fq(p_u))
    SK_client = compute_prf(0, ssid_prime, K)
    A_s_client = compute_prf(0, ssid_prime, K)

    if A_s == A_s_client:
        A_u = compute_prf(0, ssid_prime, K)
        soc.send(A_u.encode())
        print("OK")
    else:
        print("Error")
except Exception:
    print("Error")
    exit(1)
finally:
    soc.close()
