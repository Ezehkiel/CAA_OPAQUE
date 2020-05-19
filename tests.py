from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# data = b'Unaligned'  # 9 bytes
# data_bin = ' '.join('{0:08b}'.format(ord(x), 'b') for x in data.decode()).replace(" ", "")
# print(data_bin)
# key = get_random_bytes(32)
# iv = get_random_bytes(16)
# cipher1 = AES.new(key, AES.MODE_CBC, iv)
# padded_data = pad(data, 16)
# print(padded_data)
# padded_data = padded_data + ("\x00" * 16).encode()
# print(padded_data)
# ct = cipher1.encrypt(pad(data, 16))
# cipher2 = AES.new(key, AES.MODE_CBC, iv)
# pt = unpad(cipher2.decrypt(ct), 16)
# assert (data == pt)
# print("salut")
# print(' '.join('{0:08b}'.format(ord(x), 'b') for x in "salut"))
# print(' '.join('{0:08b}'.format(ord(x), 'b') for x in "\x00\x00salut"))
x = 36849853261941259454511589241605898514891521501329581469463025892166105175076
sid_bin = format(x, "0256b")
y = bytearray((36849853261941259454511589241605898514891521501329581469463025892166105175076).to_bytes(32, byteorder='big'))
print(len(y))
print(str(x))
print(y)
print(bin(x))
print(y[0])
print(y[1])
print(y[2])
print(y[3])
print(y[4])
print(y[5])

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

s = "0101000101111000010001110001111110110110000100100010100010010100101011111001011010011111110101010011101010100010100010101100110001001010111011010111110101011000010011000110001100111011001011100011100101101110110000010100010000011001001001100001010000100100"
print(bitstring_to_bytes(s))
c = bytearray(bitstring_to_bytes(s))
print(c)
# Xu_x = Xu_xy.split(',')[0]
# Xu_y = Xu_xy.split(',')[1]
# print(bin(1))
# print(bin(1<<2))
# print(bin(0<<128))
#
# print(format(1, "0128b"))
# print(format(1, "0128b"))
