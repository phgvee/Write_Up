# [WRITE-UP] ASCIS Quals 2022
## Cryptography
### 1. Crypto 1
ta có đoạn mã : ;aNHI9fO_#5s\R@77&n.0geE-78liI+AkQ^1IG>)6rPj.8kh3(68g;F6o-Ja=u$

Như thường lệ thì mình đem vào Cyberchef, và lần này thì nó decode bằng base85, tiếp tục với những base còn lại thì khi nó decode bằng base45 thì ra ngay flag :smiley: 
![](https://i.imgur.com/cP77TdF.png)

**Flag**: ASCIS{th1s_1s_just_th3_b3g1nn1ng}

### 2. Crypto 2
leak.py
```python=
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

flag = open("flag.txt", "rb").read()
nonce = Random.get_random_bytes(8)
countf = Counter.new(64, nonce)
key = Random.get_random_bytes(32)

encrypto = AES.new(key, AES.MODE_CTR, counter=countf)
encrypted = encrypto.encrypt(b"TODO:\n - ADD HARDER CHALLENGE IN CRYPTO\n - ADD FLAG TO THE CHALLENGE\n")

encrypto = AES.new(key, AES.MODE_CTR, counter=countf)
encrypted2 = encrypto.encrypt(flag)

print(f"encrypted: {encrypted}")
print(f"encrypted2: {encrypted2}")

# encrypted: b"\xb3y\xf5Ky\xed\x13\xcd\x85U1\xbb\x9c\xd8?A\xe9?P/\xc3/\x97\x97\xbf\xe3\xfam\xb9\x00\xf0_\xf3\x02s\x97\x1b\x87\xeb\t\xda\xe6\x04@0\x9a\xa8\xea\x8b\xa9\x86\x87\x1c-\xeaDI\x8b\xd1v\x1e6!\xc8'\x06_\xd4\xb9"

# encrypted2: b'\xa6e\xf2M\x10\x9cp\x8f\xcbs\x07\x9e\xc8\xe5\x12r\xd9\x1f]n\xee\x03\x89\x8c\xc0\xca\xd7\x1a\x91E\xe6e\xe3\x1e`\x9d\x02\x80\xfb@\xa8\x92tUD\x81\xeb\xc4\xa6\x84\xad\xda'
```
Nhìn vào source thì mình nhận thấy đây là AES mode CTR, và ở đây thì người ta dùng chung 1 key để encrypt 2 plaintext :
![](https://i.imgur.com/NJDQja6.png)

Vậy thì chỉ cần lấy C0 XOR P0 thì ta sẽ có E~K~(Counter), lấy C1 XOR với E~K~(Counter) thì sẽ ra được Flag :))

solve.py
```python=
from operator import xor
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from pwn import *
c1 = b"\xb3y\xf5Ky\xed\x13\xcd\x85U1\xbb\x9c\xd8?A\xe9?P/\xc3/\x97\x97\xbf\xe3\xfam\xb9\x00\xf0_\xf3\x02s\x97\x1b\x87\xeb\t\xda\xe6\x04@0\x9a\xa8\xea\x8b\xa9\x86\x87\x1c-\xeaDI\x8b\xd1v\x1e6!\xc8'\x06_\xd4\xb9"

c2 = b'\xa6e\xf2M\x10\x9cp\x8f\xcbs\x07\x9e\xc8\xe5\x12r\xd9\x1f]n\xee\x03\x89\x8c\xc0\xca\xd7\x1a\x91E\xe6e\xe3\x1e`\x9d\x02\x80\xfb@\xa8\x92tUD\x81\xeb\xc4\xa6\x84\xad\xda'
p1 = b'TODO:\n - ADD HARDER CHALLENGE IN CRYPTO\n - ADD FLAG TO THE CHALLENGE\n'
# e1 = xor(c1,p1)
e1= b'\xe76\xb1\x04C\xe73\xe0\xa5\x14u\xff\xbc\x90~\x13\xadz\x02\x0f\x80g\xd6\xdb\xf3\xa6\xb4*\xfc \xb9\x11\xd3A!\xceK\xd3\xa4\x03\xfa\xcb$\x01t\xde\x88\xac\xc7\xe8\xc1\xa7Hb\xca\x10\x01\xce\xf15Vwm\x84bH\x18\x91\xb3'
p2 = xor(c2,e1)
print(p2)
```

**Flag:** ASCIS{Congratulate_and_W3lc0me_t0_ASIS_CRYPT0_chall}