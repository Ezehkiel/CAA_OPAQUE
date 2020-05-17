from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = b'Unaligned'  # 9 bytes
data_bin = ' '.join('{0:08b}'.format(ord(x), 'b') for x in data.decode()).replace(" ", "")
print(data_bin)
key = get_random_bytes(32)
iv = get_random_bytes(16)
cipher1 = AES.new(key, AES.MODE_CBC, iv)
padded_data = pad(data, 16)
padded_data = padded_data + ("\x00" * 16).encode()
print(padded_data)
ct = cipher1.encrypt(pad(data, 16))
cipher2 = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher2.decrypt(ct), 16)
assert (data == pt)
# print(bin(1))
# print(bin(1<<2))
# print(bin(0<<128))
#
# print(format(1, "0128b"))
# print(format(1, "0128b"))
