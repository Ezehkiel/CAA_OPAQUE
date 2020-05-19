from sage.all import Integers, GF, EllipticCurve, Integer
import socket
from Crypto.Hash import BLAKE2b, HMAC, SHA256
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex

PWD = "password"
ID_SERVER = "MTI3MjExY2UyMTJi"
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


def pad(x, y):
    # on enlève 0b de la string
    x = x[2:]
    y = y[2:]

    diff_x = 256 - len(x)
    diff_y = 256 - len(y)

    return ('0' * diff_x) + x, ('0' * diff_y) + y


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


# TODO Deriver deux clé à l'aide de rw avec la même logique que SK ou A_s + On peut mettre le nonce à 0 vu que c'est du one time pad. ça fait que on a pas besoin de l'envoyer/stocker
def decrypt_c(rw, c):
    values = c.split(",")
    data = values[0]
    mac = values[1]

    secret = "YWEyZTk2NThhYzhjMjE0MmQ5YTljMzY4NDA5OTBjNzEzMjJhNDM0YThmNWIxMDRm"
    h = HMAC.new(secret.encode(), digestmod=SHA256)
    h.update(a2b_hex(data))
    try:
        h.hexverify(mac)
        cipher = AES.new(rw, AES.MODE_CTR, nonce=bytearray(1))
        plaintext = cipher.decrypt(a2b_hex(data))
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


def new_point_from_coord(string):
    return EC(FF(string.split(',')[0]), FF(string.split(',')[1]))


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


def compute_e_u(_X_u, _ssid_prim):
    _X_u_x = _X_u[0]
    _X_u_y = _X_u[1]

    x, y = pad(bin(_X_u_x), bin(_X_u_y))

    bytearray_ssid_prime = bytearray(_ssid_prim)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y + bytearray_ssid_prime)
    # On creer un Integer depuis notre hexa puis on fait modulo q
    return Fq(Integer('0x' + blk2.hexdigest()))


def compute_e_s(_X_s, _ssid_prim):
    _X_s_x = _X_s[0]
    _X_s_y = _X_s[1]

    x, y = pad(bin(_X_s_x), bin(_X_s_y))

    bytearray_ssid_prime = bytearray(_ssid_prim)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y + bytearray_ssid_prime)
    # On creer un Integer depuis notre hexa puis on fait modulo q
    return Fq(Integer('0x' + blk2.hexdigest()))


def compute_K(X_s, P_s, e_s, x_u, e_u, p_u):
    print("e_u", e_u)
    print("e_s", e_s)
    print(P_s)

    KE = ((P_s * e_s.lift()) + X_s) * (x_u + (e_u * p_u)).lift()
    x, y = pad(bin(KE[0]), bin(KE[1]))
    print("Ke point", KE)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y)
    return blk2.digest()


def compute_prf(value, prime):
    secret = "YWEyZTk2NThhYzhjMjE0MmQ5YTljMzY4NDA5OTBjNzEzMjJhNDM0YThmNWIxMDRm"
    data = str(value) + b2a_hex(prime).decode()
    h = HMAC.new(secret.encode(), digestmod=SHA256)
    h.update(data.encode())
    return h.hexdigest()


def compute_SK(prime):
    return compute_prf(0, prime)


def compute_As(prime):
    return compute_prf(1, prime)


def compute_Au(prime):
    return compute_prf(2, prime)


def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(("127.0.0.1", 12345))

# p = input("Enter your password please\n")
alpha = compute_alpha("password")
payload = "{};{}".format("{},{}".format(str(X_u[0]), str(X_u[1])), "{},{}".format(str(alpha[0]), str(alpha[1])))

soc.send(payload.encode("utf8"))  # we must encode the string to bytes
result_bytes = soc.recv(4096)  # the number means how the response can be in bytes
result_string = result_bytes.decode("utf8")  # the return will be in bytes, so decode

try:
    beta, X_s, c, A_s = get_beta_X_s_c_A_s(result_string)
    rw = compute_rw(beta)
    plaintext = decrypt_c(rw, c)
    p_u, P_s, P_u = parse_c(plaintext)
    ssid_prime = compute_ssid_prime(1, SSID, alpha)
    e_s = compute_e_s(X_s, ssid_prime)
    e_u = compute_e_u(X_u, ssid_prime)
    K = compute_K(X_s, P_s, e_s, x_u, e_u, p_u)
    print("K", K)
    SK_client = compute_SK(ssid_prime)
    A_s_client = compute_As(ssid_prime)
    if A_s == A_s_client:
        A_u = compute_Au(ssid_prime)

        soc.send(A_u.encode())
        print("OK")
    else:
        print("Error")
except Exception as e:
    print(str(e))
    print("Error")
    exit(1)
finally:
    soc.close()
