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


def pad(point):
    """
    Cette méthode va prendre les coordonnées d'un point,
    les mettre en binaire et ajouter des 0 pour avoir une taille de 256
    :param point:
    :return:
    """
    x = bin(point[0])[2:]
    y = bin(point[1])[2:]

    diff_x = 256 - len(x)
    diff_y = 256 - len(y)

    return ('0' * diff_x) + x, ('0' * diff_y) + y


def bitstring_to_bytes(s):
    """
    Cette méthode permet de transformer une string binaire en byte
    https://stackoverflow.com/questions/32675679/convert-binary-string-to-bytearray-in-python-3
    :param s: la chaine a transformer
    :return: la chaine mais en bytes
    """
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def is_point_on_G(point):
    """
    Cette méthode va vérifier que le point donné appartienne bien
    à la courbe
    :param point: le point à tester
    :return: vrai si le point est sur la courbe, faux sinon
    """

    # On vérifie que alpha n'est pas le point à l'infinie et que q*alpha soit le point à l'infinie
    if point.is_zero() and not (qq * point).is_zero():
        return False
    return True


def new_point_from_coord(string):
    """
    Cette méthode va prendre un string du forma coord_x,coord_y et va en faire un point
    :param string: les coordonnées séparé par une virgule
    :return: un nouveau point de la courbe
    """
    return EC(FF(string.split(',')[0]), FF(string.split(',')[1]))


def compute_alpha(password):
    """
    Cette méthode va calculer alpha
    :param password: le password utilisé pour pacluler alpha
    :return: alpha
    """
    blk2 = BLAKE2b.new(digest_bits=256)

    blk2.update(password.encode())
    return (r * Integer("0x" + blk2.hexdigest())).lift() * g


def get_beta_X_s_c_A_s(payload):
    """
    Cette méthode va extraire les informations recu a l'aide de séparateur
    :param payload: les données à extraire
    :return: beta, X_s, c et A_s
    """
    values = payload.split("$")
    c = values[2]
    A_s = values[3]

    try:
        beta = new_point_from_coord(values[0])
        X_s = new_point_from_coord(values[1])
        if not is_point_on_G(beta):
            raise TypeError
        return beta, X_s, c, A_s
    except Exception as e:
        raise e


def compute_rw(_beta, p):
    """
    Cette methode va calculer rw
    :param _beta: beta recu de la part du serveur
    :param p: le password de l'utilisateur
    :return: rw en digest mode
    """
    beta_calc = _beta * (1 / r).lift()

    x, y = pad(beta_calc)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    bytearray_password = bytearray(p.encode())

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_password + bytearray_x + bytearray_y)
    return blk2.digest()


def decrypt_c(rw, c):
    """
    Cette méthode va dechiffrer c
    :param rw: la clé qui va permettre de dériver les autres clé
    :param c: le texte chiffré séparé par une , avec son mac
    :return: le texte c déchiffré
    """
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
        return plaintext.decode()
    except ValueError as e:
        raise e


def parse_c(data):
    """
    Cette méthode va extraire les informations qui se trouvaient dans le texte c
    :param data: le texte c qui a été déchiffré
    :return: p_u, P_u et P_s
    """
    values = data.split(";")
    p_u = Integer(values[0])
    P_u = new_point_from_coord(values[1])
    P_s = new_point_from_coord(values[2])

    return p_u, P_u, P_s


def compute_ssid_prime(sid, ssid, alpha):
    """
    Cette méthode va calculer ssid'
    :param sid: l'id de l'utilisateur courant
    :param ssid: l'id de session courante
    :param alpha: alpha reçu du client
    :return: ssid'
    """
    # on va passer le sid et le ssid en binaire et on va padder jusqu'a 128, cela laisse des pareametre de 16 characters
    ssid_bin = ''.join('{0:08b}'.format(ord(x), 'b') for x in ssid)
    if len(ssid_bin) < 128:
        diff = 128 - len(ssid_bin)
        ssid_bin = '0' * diff + ssid_bin

    x, y = pad(alpha)
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
    :param point: le point qui va service pour le calcul
    :param prim: ssid'
    :return: e_u ou e_s
    """

    # On fait en sorte que x et y soient sur 256 bit
    x, y = pad(point)

    # On transforme tout en bytearray
    bytearray_ssid_prime = bytearray(prim)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y + bytearray_ssid_prime)
    # On creer un Integer depuis notre hexa puis on fait modulo q
    return Fq(Integer('0x' + blk2.hexdigest()))


def compute_K(X_s, P_s, e_s, x_u, e_u, p_u):
    """
    Calcule de K (HMQV)
    :param X_s: X_s du server
    :param P_s: Clé public du server
    :param e_u: e_u de la session
    :param x_u: x_s du client
    :param e_s: e_s de la session
    :param p_u: Clé privé du client
    :return: la clé K
    """

    # On vérifie que nos point soient bien sur notre courbe
    if not is_point_on_G(X_s) or not is_point_on_G(P_s):
        raise TypeError

    KE = ((P_s * e_s.lift()) + X_s) * (x_u + (e_u * p_u)).lift()
    # On fait en sorte que x et y soient sur 256 bits
    x, y = pad(KE)
    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(bytearray_x + bytearray_y)
    return blk2.digest()


def compute_prf(value, prime, K):
    """
    Cette méthode va calculer HMAC sur les données concaténées passées en paramètre
    :param value: la valeur a concatener
    :param prime: ssid' de la session
    :param K: la clé utilisé par HMAC
    :return:
    """
    data = str(value) + b2a_hex(prime).decode()
    h = HMAC.new(K, digestmod=SHA256)
    h.update(data.encode())
    return h.hexdigest()


soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(("127.0.0.1", 12346))

p = input("Enter your password please (the correct password is 'OGQ0MDM3MjAyNTNmYjY5Zjc5ODU2ZmI1M2ZiNTIzY2ZhNDYzMjZjNDU3NjQ5MmIx')\n")

""" Phase 1 Client"""
alpha = compute_alpha(p)
payload = "{};{}".format("{},{}".format(str(X_u[0]), str(X_u[1])), "{},{}".format(str(alpha[0]), str(alpha[1])))
soc.send(payload.encode("utf8"))  # we must encode the string to bytes

""" Phase 2 Client """
result_bytes = soc.recv(4096)  # the number means how the response can be in bytes
result_string = result_bytes.decode("utf8")  # the return will be in bytes, so decode

try:
    beta, X_s, c, A_s = get_beta_X_s_c_A_s(result_string)
    rw = compute_rw(beta, p)
    plaintext = decrypt_c(rw, c)
    p_u, P_u, P_s = parse_c(plaintext)
    ssid_prime = compute_ssid_prime(1, SSID, alpha)
    # C alcul de e_u
    e_u = compute_e_u_or_e_s(X_u, ssid_prime)
    # Calcul de e_s
    e_s = compute_e_u_or_e_s(X_s, ssid_prime)
    K = compute_K(X_s, P_s, e_s, x_u, e_u, Fq(p_u))
    SK_client = compute_prf(0, ssid_prime, K)
    A_s_client = compute_prf(1, ssid_prime, K)

    if A_s == A_s_client:
        A_u = compute_prf(2, ssid_prime, K)
        soc.send(A_u.encode())
        print("OK")
    else:
        print("Error")
except Exception as e:
    print("Error")
    exit(1)
finally:
    soc.close()
