**#[WRITE UP] KCSC_Training Block Cipher 3**
source.py
```python=
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
from os import urandom

FLAG = b"KCSC{???????????????????????????}"
assert len(FLAG) % 16 == 1 # hint

key1 = md5(urandom(3)).digest()
key2 = md5(urandom(3)).digest()
cipher1 = AES.new(key1, AES.MODE_ECB)
cipher2 = AES.new(key2,AES.MODE_ECB)

enc = cipher1.encrypt(pad(FLAG,16))
enc = cipher2.encrypt(enc)

print(enc.hex())

# 21477fac54cb5a246cb1434a1e39d7b34b91e5c135cd555d678f5c01b2357adc0c6205c3a4e3a8e6fb37c927de0eec95

```
Nhìn vào source thì mình có thể đoán được đây là [Meet-in-the-middle attack](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack). Ở đây ciphertext sẽ được mã hóa 2 lần với 2 Key khác nhau: 
![](https://i.imgur.com/MVuveqN.png)

Từ ảnh trên mình có thể viết lại như sau:
![](https://i.imgur.com/lmTrQSy.png)

Như vậy thì mình cần tìm K1,K2 thỏa mãn phương trình trên thì sẽ thu được plaintext ban đầu :kissing_cat: 

Ở hàm E thì đầu vào của nó là một Plaintext nhưng giờ mình vẫn chưa có Plaintext nào cả :smiley: . Nhưng may là chúng ta có hint là len(flag)%16==1. Có nghĩa là cái ciphertext mình thu được thì 15 bytes cuối sẽ là \x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f. Và kí tự cuối cùng của flag chính là '}'. Giờ thì mình đã có đủ plaintext với độ dài 16 bytes : 
P : '}\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'.

Giờ mình có Ciphertext và cả Plaintext rồi nên chỉ cần brute-force key và tìm ra k1,k2 thõa mãn điều kiện ở hình trên là mình sẽ thu được flag =)).

solve.py
```python=
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import string
c=bytes.fromhex('21477fac54cb5a246cb1434a1e39d7b34b91e5c135cd555d678f5c01b2357adc0c6205c3a4e3a8e6fb37c927de0eec95')
c1=c[-16:]
key1 = b''
key2 = b''

pad = b'}'+bytes([15])*15
decrypt={}
for i in range(0,256):
    for j in range(0,256):
        for k in range(0,256):
            a = bytes([i])+bytes([j])+bytes([k])
            key = md5(a).digest()
            cipher1 = AES.new(key, AES.MODE_ECB)
            x = cipher1.decrypt(c1)
            decrypt[x] = key
            

encrypt={}
for i in range(0,256):
    for j in range(0,256):
        for k in range(0,256):
            a = bytes([i])+bytes([j])+bytes([k])
            key = md5(a).digest()
            cipher2 = AES.new(key, AES.MODE_ECB)   
            x =cipher2.encrypt(pad)
            encrypt[x] = key

decrypt_set =  set(decrypt.keys())
encrypt_set = set(encrypt.keys())

intersection = encrypt_set.intersection(decrypt_set).pop()

key1 = encrypt[intersection]
key2= decrypt[intersection]


cipher1 = AES.new(key1, AES.MODE_ECB)
cipher2 = AES.new(key2,AES.MODE_ECB)

flag = cipher2.decrypt(c)
flag = cipher1.decrypt(flag)
print(flag)


```
**flag : KCSC{MeEt_In_tHe_mIdDLe_AttaCk}**