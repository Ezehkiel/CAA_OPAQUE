from Crypto.Protocol.KDF import scrypt
from sage.all import Integers, GF, EllipticCurve, Integer
import socket
from Crypto.Hash import BLAKE2b, HMAC, SHA256
from Crypto.Cipher import AES
from binascii import b2a_hex

# tow = 128
SSID = "YWM0MjEwYzkxNzll"
PWD = "password"
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

k_s = Fq.random_element()
p_s = Fq.random_element()
p_u = Fq.random_element()

P_s = p_s.lift() * g
P_u = p_u.lift() * g


def pad(point):
    x = bin(point[0])[2:]
    y = bin(point[1])[2:]

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


def compute_rw():
    # On hash le password
    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(PWD.encode())
    # On calcule H' (ks * H(pwd) * g)
    H_prime = (k_s * Integer("0x" + blk2.hexdigest())).lift() * g

    # On fait en sorte que x et y de H' soient de la même taille en les paddant
    x, y = pad(H_prime)

    bytearray_x = bytearray(bitstring_to_bytes(x))
    bytearray_y = bytearray(bitstring_to_bytes(y))

    # On passe le password en byrearray pour le concatener avec x et y de H'
    bytearray_password = bytearray(PWD.encode())
    data = bytearray_password + bytearray_x + bytearray_y

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(data)
    rw = blk2.digest()
    return rw


def compute_c(key):
    """
    Cette methode va concatener certaines infos généré pour un certain client puis le chiffrer.
    On utiliser AES et HMAC, de ce fait il nous faut deux clés. On va donc utiliser une KDF.
    :param key: master key qui sera utilisé pour générer les autres clés
    :return: le text chiffré ainsi que le mac
    """

    # KDF on calcule une fois avec 0 et une fois avec 1. Pour le sel la documentation
    # conseille quelque chose d'une longueur de 16bytes qui n'a pas besoin d'être secret
    # c'est pourquoi j'ai choisi de prendre le SSID car le client doit aussi connaitre le sel
    key_aes = scrypt('\x00'.encode() + key, SSID, 32, N=2 ** 14, r=8, p=1)
    key_hmac = scrypt('\x01'.encode() + key, SSID, 32, N=2 ** 14, r=8, p=1)

    cipher = AES.new(key_aes, AES.MODE_CTR, nonce=bytearray(1))
    # On concatène avec des séparateurs les datas que on veut chiffrer pour pouvoir les récuperer après
    data = str(p_u) + ";" + str(P_u[0]) + "," + str(P_u[1]) + ";" + str(P_s[0]) + "," + str(P_s[1])
    c = cipher.encrypt(data.encode())
    h = HMAC.new(key_hmac, digestmod=SHA256)
    h.update(c)
    return b2a_hex(c), h.hexdigest()


def write_file(c_final, c_mac, id_user):
    """
    Sauvegarde les données dans un fichier pour pouvoir les récuperer plus tard
    :param c_final: le texte c chiffré
    :param c_mac: le mac de c
    :param id_user: l'id de l'utilisateur
    """
    f = open("secretfile.txt", "w")
    f.write("{};{};{};{};{};{}".format(id_user, str(k_s), str(p_s), "{},{}".format(str(P_s[0]), str(P_s[1])),
                                       "{},{}".format(str(P_u[0]), str(P_u[1])),
                                       "{},{}".format(c_final.decode(), c_mac)))
    f.close()


def get_alpha_and_x_u(payload):
    """
    Cette méthode va extraire les informations à l'aide de séparateur afin d'en extraire alpha et X_u
    :param payload: la chaine de charactères entière
    :return: alpha et X_u sous forme de points
    """
    values = payload.split(";")
    X_u_points = values[0].split(",")
    alpha_points = values[1].split(",")

    try:
        # On construit les points à l'aide des valeurs reçues. Si les coords ne sont pas sur la courbe
        # cela va creer une exception
        X_u = new_point_from_coord(values[0])
        alpha = new_point_from_coord(values[1])
        # On vérifie que alpha n'est pas le point à l'infinie et que q*alpha soit le point à l'infinie
        if alpha.is_zero() and not (qq * alpha).is_zero():
            raise TypeError
        return X_u, alpha
    except TypeError:
        raise


def fetch_in_file(sid=1):
    """
    Lecture du fichier
    :param sid: l'id de l'utilisateur concerné
    :return: un tableau avec toutes les valeurs de la ligne
    """
    f = open("secretfile.txt", "r")
    lines = f.readlines()

    for line in lines:
        tokens = line.split(";")
        # On regarde si la ligne est celle pour notre utilisateur, si c'est le cas on la return
        if tokens[0] == str(sid):
            return tokens


def compute_ssid_prime(sid, ssid, alpha):
    """
    Cette méthode va calculer ssid'
    :param sid: l'id de l'utilisateur courant
    :param ssid: l'id de session courante
    :param alpha: alpha reçu du client
    :return: ssid'
    """
    # on va passer le ssid en binaire et on va padder jusqu'a 128, cela laisse des pareametre de 16 characters
    ssid_bin = ''.join('{0:08b}'.format(ord(x), 'b') for x in ssid)
    if len(ssid_bin) < 128:
        diff = 128 - len(ssid_bin)
        ssid_bin = '0' * diff + ssid_bin

    # On fait en sorte que x et y soit sur 256 bit
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
    :param point: X_u
    :param prim:  ssid'
    :return: e_u
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


def compute_K(X_u, P_u, e_u, x_s, e_s, p_s):
    """
    Calcule de K (HMQV)
    :param X_u: X_u du client
    :param P_u: Private key du client
    :param e_u: e_u de la session
    :param x_s: x_s du serveur
    :param e_s: e_s de la session
    :param p_s: public key du serveur
    :return:
    """
    if not is_point_on_G(X_u) or not is_point_on_G(P_u):
        raise TypeError

    KE = ((P_u * e_u.lift()) + X_u) * (x_s + (e_s * p_s)).lift()
    # On fait en sorte que x et y soient de la même longueur (256 bits)
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


def client(conn, ip, port, MAX_BUFFER_SIZE=4096):
    # the input is in bytes, so decode it
    input_from_client_bytes = conn.recv(MAX_BUFFER_SIZE)

    # decode input and strip the end of line
    input_from_client = input_from_client_bytes.decode("utf8").rstrip()
    try:
        """ Phase 1 server"""
        X_u, alpha = get_alpha_and_x_u(input_from_client)
        file_info = fetch_in_file()
        P_u_coords = file_info[4]
        P_u = EC(FF(P_u_coords.split(',')[0]), FF(P_u_coords.split(',')[1]))
        p_s = Fq(Integer(file_info[2]))
        x_s = Fq.random_element()
        X_s = x_s.lift() * g
        beta = alpha * Fq(file_info[1]).lift()
        ssid_prime = compute_ssid_prime(1, SSID, alpha)  # 1 is the user 1
        # C alcul de e_u
        e_u = compute_e_u_or_e_s(X_u, ssid_prime)
        # Calcul de e_s
        e_s = compute_e_u_or_e_s(X_s, ssid_prime)
        K = compute_K(X_u, P_u, e_u, x_s, e_s, p_s)
        SK = compute_prf(0, ssid_prime, K)
        A_s = compute_prf(1, ssid_prime, K)
        return_payload = "{}${}${}${}".format("{},{}".format(str(beta[0]), str(beta[1])),
                                              "{},{}".format(str(X_s[0]), str(X_s[1])), file_info[5], A_s)

        vysl = return_payload.encode("utf8")  # encode the result string
        conn.sendall(vysl)  # send it to client

        """ Phase 2 server """
        # the input is in bytes, so decode it
        input_from_client_bytes = conn.recv(MAX_BUFFER_SIZE)
        # decode input and strip the end of line
        input_from_client = input_from_client_bytes.decode("utf8").rstrip()
        A_u = compute_prf(2, ssid_prime, K)
        if A_u == input_from_client:
            print("OK")
        else:
            raise TypeError

    except Exception:
        print("Error")
        exit(1)
    finally:
        conn.close()
        print('Connection ' + ip + ':' + port + " ended")


def start_server():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')

    try:
        soc.bind(("127.0.0.1", 12346))
        print('Socket bind complete')
    except socket.error as msg:
        import sys
        print('Bind failed. Error : ' + str(sys.exc_info()))
        sys.exit()

    # Start listening on socket
    soc.listen(10)
    print('Socket now listening')

    conn, addr = soc.accept()
    ip, port = str(addr[0]), str(addr[1])
    print('Accepting connection from ' + ip + ':' + port)
    client(conn, ip, port)
    soc.close()


c_final, c_mac = compute_c(compute_rw())
write_file(c_final, c_mac, 1)  # 1 is the user id

start_server()
