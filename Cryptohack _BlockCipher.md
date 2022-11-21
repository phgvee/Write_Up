# [WRITE UP] CRYPTOHACK _BlockCipher

## 1. ECB CBC WTF

![](https://i.imgur.com/ZHArE2m.png)

Có thể thấy rằng hàm mã hóa thì dùng AES mode CBC nhưng hàm giải mã lại dùng AES mode ECB. Khi chúng ta request ‘/ecbcbcwtf/encrypt_flag/’ thì server trả về hex(iv || AES-CBC(flag)). Nhưng khi mình request ‘/ecbcbcwtf/decrypt/ciphertext/’ thì server chỉ decrypt AES-ECB

Ở đây hàm decrypt đã thiếu đi bước XOR với các khối được mã hóa . Vậy nên sau khi thu được decrypt thì mình sẽ tiếp tục hoàn thiện bước XOR để thu được flag

solve.py

```python=
import requests
from Crypto.Cipher import AES
from Crypto.Util.number import *

def decrypted(x):
    c = x.hex()
    url = "http://aes.cryptohack.org/ecbcbcwtf/"
    r = requests.get(f"{url}/decrypt/{c}")
    data = r.json()
    return bytes.fromhex(data["plaintext"])

   

url ="http://aes.cryptohack.org/ecbcbcwtf/"
r = requests.get(f"{url}/encrypt_flag")
c = r.json()
ciphertext =  bytes.fromhex(c["ciphertext"])
#ciphertext = 48
iv = ciphertext[:16]
c1 = ciphertext[16:32]
c2 = ciphertext[32: ]

d1 = decrypted(c1)
d2 = decrypted(c2)
flag1 = long_to_bytes(bytes_to_long(d1)^bytes_to_long(iv))
flag2 = long_to_bytes(bytes_to_long(d2)^bytes_to_long(c1))
print(flag1+flag2)

```
**flag** : crypto{3cb_5uck5_4v01d_17_!!!!!}


## 2.ECB ORACLE

![](https://i.imgur.com/vL4a1T3.png)

AES.ECB có một đặc điểm là nếu plaintext giống nhau thì sẽ cho ciphertext giống nhau. Vậy là nếu mình nhập vào đoạn plaintext giống nhau có độ dài là bội của 16 (mục đích là để cho flag nằm trên một khối) thì khi mình giảm đi độ dài của plaintext thì kí tự của flag sẽ bị đẩy lên trên , giờ chỉ cần brute-force và so sánh là biết được kí tự đó.

solve.py
```python=
import requests
import string
url = "http://aes.cryptohack.org/ecb_oracle/"
s0 = 'a'*16
s1 = 'a'*16
k = string.printable
flag = ''
t = ''
for i in range (31):
    s1 =s1[1:]+t
    for  j in k:
        c = s0+s1+j+'a'*(31-i)
        c = c.encode().hex()
        r = requests.get(f"{url}/encrypt/{c}")
        data = r.json()
        cipher = data["ciphertext"]
        cipher = bytes.fromhex(cipher)
        if(cipher[16:32]==cipher[48:64]):
            flag +=j
            t=j
            print(flag)
            break

```
**flag:** crypto{p3n6u1n5_h473_3cb}

## 3.FLIPPING COOKIE

![](https://i.imgur.com/uGDWuF6.png)

khi request ‘/flipping_cookie/get_cookie/’ thì server trả lại cho mình json chứa ciphertext: hex(iv || AES-CBC(pad(cookie)))

Khi mình request‘/flipping_cookie/check_admin/cookie/iv/’ thì server sẽ decrypt đoạn ciphertext và kiểm tra xem có ‘admin=True’ trong plaintext hay không, nếu có thì sẽ trả lại flag nếu không sẽ báo lỗi.

Vấn đề là đoạn ciphertext mình nhận được chỉ chứa ‘admin=False’ và mình sẽ dùng kĩ thuật Bit Flipping Attack để chuyển ‘admin=False’ thành ‘admin=True’ bằng cách chỉnh sửa đoạn iv:

Mình biết được vị trí của chữ ‘F’ là 6 trong ‘admin=False’:

Bình thường nếu mình gửi y chang iv và đoạn ciphertext mình nhận được thì server sẽ decrypt như sau: 
![](https://i.imgur.com/I2BSWws.png)


Bây giờ mình sẽ thay:
![](https://i.imgur.com/zG090pB.png)

Khi mình gửi lại đoạn IV’ đã được chỉnh sửa thì server sẽ decrypt như sau:
![](https://i.imgur.com/DE7iHQ7.png)

Mình cũng sẽ làm tương tự đối với vị trí của IV tương ứng với vị trí của ‘a’,‘l’,‘s’,‘e’ trong ‘admin=False’:

```python=
import requests
from Crypto.Util.number import *
url = "http://aes.cryptohack.org/flipping_cookie/"
r = requests.get(f"{url}/get_cookie")
data = r.json()
cookie = data["cookie"]
iv =bytes.fromhex(cookie[:32])
ciphertext =bytes.fromhex(cookie[32:])

iv1 = iv[:6] +bytes([iv[6]^ord('F')^ord('T')])+bytes([iv[7]^ord('a')^ord('r')])+bytes([iv[8]^ord('l')^ord('u')])+bytes([iv[9]^ord('s')^ord('e')])+bytes([iv[10]^ord('e')^ord(';')])+iv[11:]


# iv[6] = iv[6]^ord('F')^ord('T')
# iv[7] = iv[7]^ord('a')^ord('r')
# iv[8] = iv[8]^ord('l')^ord('u')
# iv[9] = iv[9]^ord('s')^ord('e')
# iv[10] = iv[10]^ord('e')^ord(';')
iv1 = iv1.hex()
ciphertext = ciphertext.hex()
url1 =  "http://aes.cryptohack.org/flipping_cookie/check_admin"
a = requests.get(f"{url1}/{ciphertext}/{iv1}")
data2 = a.json()
print(data2)

```
**flag:** crypto{4u7h3n71c4710n_15_3553n714l}

## 4.Lazy CBC

source.py

```python=
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/lazy_cbc/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    encrypted = cipher.encrypt(plaintext)

    return {"ciphertext": encrypted.hex()}


@chal.route('/lazy_cbc/get_flag/<key>/')
def get_flag(key):
    key = bytes.fromhex(key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}


@chal.route('/lazy_cbc/receive/<ciphertext>/')
def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode() # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}

```

Ở bài này thì IV lại chính là key, khi nhập vào plaintext thì nó sẽ trả về ciphertext ở dạng hex.

vậy nếu tìm được IV thì mình sẽ tìm được flag theo đúng yêu cầu của đề bài

Ta có: ![](https://i.imgur.com/iEcA2LV.png)

Nếu cho : ![](https://i.imgur.com/NhM8hcJ.png)


Thì : ![](https://i.imgur.com/GXBjqAB.png)

```python=
import requests
from pwn import *
url = "http://aes.cryptohack.org/lazy_cbc/"
p =b'b'*48
p=p.hex()
r1 = requests.get(f"{url}/encrypt/{p}")
data = r1.json()
c = data["ciphertext"]
ciphertext = bytes.fromhex(c)
ciphertext2 = (ciphertext[:16] + bytes([0]*16) + ciphertext[:16])
ciphertext2 = ciphertext2.hex()
r2 = requests.get(f"{url}/receive/{ciphertext2}")
data2 = r2.json()
invalid_plaintext =bytes.fromhex('626262626262626262626262626262622d3f5700f199df13e1c2b5820ffbd1a102d98bb76e3e2908d5900c88e37f413d')
print(len(invalid_plaintext))
iv = xor(invalid_plaintext[:16], invalid_plaintext[32:48])
iv = iv.hex()
r3 = requests.get(f"{url}/get_flag/{iv}")
data3 = r3.json()
flag = bytes.fromhex(data3["plaintext"])
print(flag)
```

**flag:** crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}

## 5.TRIPLE DES

![](https://i.imgur.com/XE0STAG.png)

* Nhìn vào source thì mình biết được rằng nếu mình request /triple_des/encrypt_flag/key/ thì server sẽ trả về AES-CBC(pad(flag)) với key mình chọn và nếu mình request /triple_des/encrypt/<key>/<plaintext>/ thì server sẽ trả về AES-CBC(pad(plaintext))
* Lưu ý rằng chall chỉ có hàm encrypt nên mình sẽ dùng những khóa yếu để tìm lại flag
* Khóa yếu là những khóa sao cho:
    ![](https://i.imgur.com/H9d87Wz.png)

![](https://i.imgur.com/nUHxu4d.png)

solve.py
```python=
import requests
url = 'http://aes.cryptohack.org/triple_des/'
k1 = b'\x01'*8
k2 = b'\xfe'*8
key = k1.hex()+k2.hex()
r = requests.get(f"{url}/encrypt_flag/{key}")
data1 = r.json()
ciphertext = data1['ciphertext']
r1 = requests.get(f"{url}/encrypt/{key}/{ciphertext}")
data2 = r1.json()
flag = bytes.fromhex(data2['ciphertext'])
print(flag)
```
**flag:**  crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}