# [WRITE UP] KCSC Traning - Block Cipher3

nc 45.77.45.157 2000

source.py

```python=
from Crypto.Cipher import AES
from os import urandom
import string


chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '!_{}'
FLAG = b'KCSC{___}'
assert all(i in chars for i in FLAG.decode())


def pad(msg, block_size):
    pad_len = 16 - len(msg) % block_size
    return msg + bytes([pad_len])*pad_len


def encrypt(key):
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(pad(FLAG,16)) ).hex()
    
    
def decrypt(enc,key):
    enc = bytes.fromhex(enc)
    iv = enc[:16]
    ciphertext = enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if all(i == pad_len for i in decrypted[-pad_len:]):
        return b'Decrypted successfully.'
    else:
        return b'Incorrect padding.'


if __name__ == '__main__':
    key = urandom(16)
    while True:
        choice = input()
        if choice == 'encrypt':
            print(encrypt(key))
        elif choice == 'decrypt':
            c = input('Ciphertext: ')
            try:
                print(decrypt(c,key))
            except:
                continue
```
Nhìn vào source thì mình có thể nhận thấy đây là Padding Oracle Attack. Server sẽ cho mình hai lựa chọn là encrypt hoặc decrypt. Nếu chọn encrypt thì nó sẽ trả về một đoạn ciphertext. Nếu chọn decrypt thì nó sẽ yêu cầu mình nhập ciphertext vào và sẽ trả về 'Decrypted successfully' nếu như ciphertext nhập vào được decrypt và trả về đúng định dạng padding , ngược lại trả về 'Incorrect padding'.

:::success
:Bulb: Các bạn có thể đọc [Padding Oracle Attack](https://phgvee.wordpress.com/2022/11/23/crypto-padding-oracle-attack/?fbclid=IwAR1uBbZO9cqI_Kyfu2g23bCBBiiLnFND9Ck3-X0E7W2c7sab-W0GdQrIOiU) để hiểu rõ cách mà nó hoạt động 
:::

Chúng ta có : 

* C: Khối ciphertext cần giải mã
* C' : khối sau khi trải qua hàm giải mã ( chưa XOR nha ).
* A: khối dùng để brute-force 
* P : plaintext

Cách thực hiện: 
* Đầu tiên mình sẽ cho khối A 16 bytes( 15 bytes đầu cho gì cũng được, bytes cuối brute-force trong khoảng 0-255).
* Gửi lên server một khối (IV + A), khi nào nhận lại được 'Decrypted successfully' thì dừng brute-force
* Giờ thì mình đã biết được bytes cuối của khối A là gì và giờ mình xor nó với \x01 ( theo tiêu chuẩn padding) thì mình sẽ tìn được byte cuối của C'.
* Lập đi lập lại ( nhớ thay đổi số bytes brute-force và bytes dùng để xor) để tìm được cả khối C'.
* Lúc này mình chỉ cần xor C' với khối A ban đầu là tìm được P.

solve.py
```python=
from pwn import *

io = remote('localhost',2004)
io.sendline(b'encrypt')
data = io.recvuntil(b'\n', drop=True)
data = bytes.fromhex(data.decode())
iv = data[:16]
ciphertext = data[16:]
flag = b''
for i in range(2):
    b = ciphertext[i*16:i*16+16]
    con_plain = b''
    block_after = [0]*16
    con_ciphertext =bytes([0]*16)
    ct = b''
    for j in range(1,17):
        for k in range(0,255):
            con_ciphertext = con_ciphertext[:-j] + bytes([k]) + con_plain
            ct = iv + con_ciphertext + b
            io.sendline(b'decrypt')
            io.recvuntil(b'Ciphertext: ')
            io.sendline(ct.hex().encode())
            res = io.recvuntil(b'\n', drop= True)
            if(res == b'Decrypted successfully.'):
                block_after[-j] = k ^ j
                con_plain = b''
                con_plain = xor(bytes([j+1]*j),bytes(block_after[-j:]) )
                break
    
    flag += xor(bytes(block_after),data[i*16:i*16+16])

print(flag)
io.interactive()

```
**flag:** KCSC{CBC_p4dd1ng_0racle_}