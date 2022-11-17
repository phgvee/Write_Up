# [WRITE-UP] Block_Cipher1
Mình có một file source như này : 

source.py

nc 45.77.45.157 2000

```python=
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import choice
from os import urandom

FLAG = b'KCSC{?????????????????????}'

if __name__ == '__main__':
    for i in range(100):
        x = choice(['ECB','CBC'])
        if x == 'ECB':
            cipher = AES.new(urandom(16), AES.MODE_ECB)
        else:
            cipher = AES.new(urandom(16), AES.MODE_CBC, urandom(16))

        try:
            msg = bytes.fromhex(input())
            assert len(msg) <= 16
            print(cipher.encrypt(pad(msg,16)).hex())
            ans = input()
            assert ans == x
            print('Correct!')
        except:
            print("Exiting...")
            quit()

    print(FLAG)
```
Nhìn vào source thì mình có thể nhận ra là khi mình gửi cho server 1 chuỗi hex (độ dài của chuỗi này phải <=16) thì server sẽ trả lại một đoạn ciphertext. Và nhiệm vụ của mình là đoán xem nó đang dùng mode mã hóa nào của AES.

Ở đây có 2 option là 'ECB'và'CBC'. Nếu đoán đúng 100 lần thì mình sẽ nhận được flag :triangular_flag_on_post: 

Dưới đây là hình minh họa:
![](https://i.imgur.com/M0FC6J9.png)

Vấn đề bây giờ là làm sao để biết khi nào nó đang dùng mode 'CBC' và khi nào dùng 'ECB' :thinking_face: 

Giờ hãy nhìn lại sơ đồ mã hóa của CBC và ECB:
![](https://i.imgur.com/3d4Ar5W.png)

![](https://i.imgur.com/4M5Wmmu.png)

Trong file source, khi mã hóa thì phần msg được pad thêm 16 bytes. Và mặc định là 16 bytes đó sẽ là \x10.


Vậy nên ban đầu mình sẽ chọn msg là 16 byte \x10 và sau khi pad msg sẽ là 32 bytes \x10. 32 bytes này nếu nó được mã hóa bằng ECB thì phần ciphertext nó sẽ bị lặp lại. Đây chính là mấu chốt để phân biệt ECB và CBC. Giờ thì viết code và get flag thui :kissing_smiling_eyes: 

```python=
from pwn import *
data =b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10' 

io = remote('45.77.45.157',2000)

for i in range(100):
    io.sendline(data.hex().encode())
    a=(io.recv(1024)).strip()
    if(a[0:len(a)//2]==a[len(a)//2:]):
        io.sendline('ECB')
    else:
        io.sendline('CBC')
    print(io.recvline())

io.interactive()

```
Flag: KCSC{Bingo!_PKCS#7_padding}