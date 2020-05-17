from sage.all import Integers, GF, EllipticCurve, Integer
import socket
from Crypto.Hash import BLAKE2b, HMAC, SHA256
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex

# tow = 128
SSID = "YWM0MjEwYzkxNzll"
ID_SERVER = "MTI3MjExY2UyMTJi"
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


def pad(x, y):
    # on enlève 0b de la string
    x = x[2:]
    y = y[2:]
    # On regarde la différence de longuezr etre les deux
    diff = abs(len(x) - len(y))
    # Si pas de différence on laisse comme ça
    if not diff:
        return x, y

    # Si x est plus grand on ajout diff * 0 à y et si y est plus grand on fait la même chose mais pour x
    if len(x) > len(y):
        return x, ('0' * diff) + y
    elif len(x) < len(y):
        return ('0' * diff) + x, y


def compute_rw():
    # On hash le password
    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update(PWD.encode())
    # On calcule H' (ks * H(pwd) * g)
    H_prime = (k_s * Integer("0x" + blk2.hexdigest())).lift() * g
    H_prime_x = H_prime[0]
    H_prime_y = H_prime[1]

    # On fait en sorte que x et y de H' soient de la même taille en les paddant
    x, y = pad(bin(H_prime_x), bin(H_prime_y))
    # On les concatène pour ensuite repasser en int pour ensuite repasser en binaire
    x_y = x + y
    x_y = int(x_y, base=2)
    # On passe le password en binaire pour le concatener avec x et y de H'
    password_bin = ' '.join(format(ord(x), 'b') for x in PWD).replace(" ", "")
    padded_password, padded_h_prime = pad(bin(int(password_bin, base=2)), bin(x_y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update((padded_password + padded_h_prime).encode())
    rw = blk2.hexdigest()
    print("RW: ", rw)
    # On met rw en format binaire
    rw = bin(Integer('0x' + rw))
    # On regarde s'il y a des 0 qui ont été enlevé et on les rajoute
    missing_bit = 256 - len(rw[2:])
    rw = ('0' * missing_bit) + rw[2:]

    return rw


def compute_c(key):
    cipher = AES.new(bitstring_to_bytes(key), AES.MODE_CTR)
    # On concatène avec des séparateurs les datas que on veut chiffrer pour pouvoir les récuperer après
    data = str(p_u) + ";" + str(P_u[0]) + "," + str(P_u[1]) + ";" + str(P_s[0]) + "," + str(P_s[1])
    secret = "YWEyZTk2NThhYzhjMjE0MmQ5YTljMzY4NDA5OTBjNzEzMjJhNDM0YThmNWIxMDRm"
    c = cipher.encrypt(data.encode())

    h = HMAC.new(secret.encode(), digestmod=SHA256)
    h.update(c)
    return b2a_hex(c), h.hexdigest(), b2a_hex(cipher.nonce)


def write_file(c_final, c_mac, nonce, id_user=0):
    f = open("secretfile.txt", "w")
    f.write("{};{};{};{};{};{}".format(id_user, str(k_s), str(p_s), "{},{}".format(str(P_s[0]), str(P_s[1])),
                                       "{},{}".format(str(P_u[0]), str(P_u[1])),
                                       "{},{},{}".format(c_final.decode(), c_mac, nonce.decode())))
    f.close()


def get_alpha_and_x_u(payload):
    values = payload.split(";")
    X_u_points = values[0].split(",")
    alpha_points = values[1].split(",")

    try:
        X_u = EC(FF(X_u_points[0]), FF(X_u_points[1]))
        alpha = EC(FF(alpha_points[0]), FF(alpha_points[1]))
        return X_u, alpha
    except TypeError:
        raise


def fetch_in_file(sid=0):
    f = open("secretfile.txt", "r")
    Lines = f.readlines()

    # Strips the newline character
    for line in Lines:
        tokens = line.split(";")
        if tokens[0] == str(sid):
            return tokens


def compute_ssid_prime(sid, ssid, alpha):
    # on va passer le sid et le ssid en binaire et on va padder jusqu'a 128, cela laisse des pareametre de 16 characters
    sid_bin = format(sid, "0128b")
    ssid_bin = ' '.join('{0:08b}'.format(ord(x), 'b') for x in ssid).replace(" ", "")
    if len(ssid_bin) < 128:
        diff = 128 - len(ssid_bin)
        ssid_bin = '0' * diff + ssid_bin

    alpha_x = alpha[0]
    alpha_y = alpha[1]

    x, y = pad(bin(alpha_x), bin(alpha_y))

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update((sid_bin + ssid_bin + x + y).encode())

    return blk2.hexdigest()


def compute_e_u(_X_u, _ssid_prim):
    _X_u_x = _X_u[0]
    _X_u_y = _X_u[1]

    x, y = pad(bin(_X_u_x), bin(_X_u_y))

    # On transforme le ID_SERVER en binaire
    server_id_bin = ' '.join('{0:08b}'.format(ord(x), 'b') for x in ID_SERVER).replace(" ", "")
    # On regarde s'il manque des 0 devant
    if len(server_id_bin) < 128:
        # S'il en manque on les ajoute
        diff = 128 - len(server_id_bin)
        server_id_bin = '0' * diff + server_id_bin

    # _ssid_prime est une string donc on le passe en Integer puis on veut sa forme binaire
    # Une fois en binaire il faut ajouter les 0 qui n'apparaisse pas devant
    _ssid_prim = bin(Integer('0x' + _ssid_prim))
    # On regarde combien de 0 il manque devant
    missing_bit = 256 - len(_ssid_prim[2:])
    # On ajouter les 0 manquant
    _ssid_prim = ('0' * missing_bit) + _ssid_prim[2:]

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update((x + y + server_id_bin + _ssid_prim).encode())
    # On creer un Integer depuis notre hexa puis on fait modulo q
    return Fq(Integer('0x' + blk2.hexdigest()))


def compute_e_s(_X_s, _ssid_prim, _sid):
    _X_s_x = _X_s[0]
    _X_s_y = _X_s[1]

    x, y = pad(bin(_X_s_x), bin(_X_s_y))

    # On transforme le ID_SERVER en binaire
    sid_bin = format(_sid, "0128b")

    # _ssid_prime est une string donc on le passe en Integer puis on veut sa forme binaire
    # Une fois en binaire il faut ajouter les 0 qui n'apparaisse pas devant
    _ssid_prim = bin(Integer('0x' + _ssid_prim))
    # On regarde combien de 0 il manque devant
    missing_bit = 256 - len(_ssid_prim[2:])
    # On ajouter les 0 manquants
    _ssid_prim = ('0' * missing_bit) + _ssid_prim[2:]

    blk2 = BLAKE2b.new(digest_bits=256)
    blk2.update((x + y + sid_bin + _ssid_prim).encode())
    # On creer un Integer depuis notre hexa puis on fait modulo q
    return Fq(Integer('0x' + blk2.hexdigest()))


def compute_prf(value, prime):
    secret = "YWEyZTk2NThhYzhjMjE0MmQ5YTljMzY4NDA5OTBjNzEzMjJhNDM0YThmNWIxMDRm"
    data = str(value) + prime
    h = HMAC.new(secret.encode(), digestmod=SHA256)
    h.update(data.encode())
    return h.hexdigest()


def compute_SK(prime):
    return compute_prf(0, prime)


def compute_As(prime):
    return compute_prf(1, prime)


def compute_Au(prime):
    return compute_prf(2, prime)


def client(conn, ip, port, MAX_BUFFER_SIZE=4096):
    # the input is in bytes, so decode it
    input_from_client_bytes = conn.recv(MAX_BUFFER_SIZE)

    # decode input and strip the end of line
    input_from_client = input_from_client_bytes.decode("utf8").rstrip()
    try:
        X_u, alpha = get_alpha_and_x_u(input_from_client)
        file_info = fetch_in_file()
        x_s = Fq.random_element()
        X_s = x_s.lift() * g
        beta = alpha * Fq(file_info[1]).lift()
        ssid_prime = compute_ssid_prime(0, SSID, alpha)
        e_u = compute_e_u(X_u, ssid_prime)
        e_s = compute_e_s(X_s, ssid_prime, 0)  # 0 is the user id
        K = ""
        # TODO Il faudra calculer le clé et la donner aux deux methodes suivante
        SK = compute_SK(ssid_prime)
        A_s = compute_As(ssid_prime)
        return_payload = "{}${}${}${}".format("{},{}".format(str(beta[0]), str(beta[1])),
                                              "{},{}".format(str(X_s[0]), str(X_s[1])), file_info[5], A_s)
        print(return_payload)

        # print("Result of processing {} is: {}".format(input_from_client, res))
        vysl = return_payload.encode("utf8")  # encode the result string
        conn.sendall(vysl)  # send it to client

        # the input is in bytes, so decode it
        input_from_client_bytes = conn.recv(MAX_BUFFER_SIZE)

        # decode input and strip the end of line
        input_from_client = input_from_client_bytes.decode("utf8").rstrip()
        A_u = compute_Au(ssid_prime)
        if A_u == input_from_client:
            print("OK")
        else:
            raise

    except:
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
        soc.bind(("127.0.0.1", 12345))
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


def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


rw_final = compute_rw()
c_final, c_mac, nonce = compute_c(rw_final)
write_file(c_final, c_mac, nonce, 0)  # 0 is the user id

start_server()
