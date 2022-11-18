#**[WRITE UP] Cryptohack - Symmetric Cipher - Modes of Operation Starter**

Dưới phần mô tả của challange thì có một đường link, nhấp vào link thì mình sẽ được dẫn đến page có thử thách.

Chúng ta sẽ tương tác với challenge qua các chức năng ở trong page.Hoặc có thể sử dụng GET/ request trong package request ở python.

source.py
```python=
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/block_cipher_starter/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/block_cipher_starter/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}
```
Nhìn vào @chal.route dẫn đến encrypt_flag, gõ 'encrypt_flag' lên thanh url của page thì ta sẽ nhận được ciphertext.

![](https://i.imgur.com/aec1ptB.png)

Đến đây thì chỉ cần thả ciphertext vào trong mục decrypt thì ta sẽ thu được plaintext:

![](https://i.imgur.com/xnexs8J.png)

Plaintext hiện tại thì đang ở dạng hex, giờ chỉ cần thả vào trong hex decode là sẽ lụm đc flag thoi :kissing_cat: 

![](https://i.imgur.com/lnqQLVc.png)

Và bài này thì mình cũng có dùng package request trong python , các bạn có thể tham khảo thử : 

```python=
import requests
url = 'http://aes.cryptohack.org/block_cipher_starter'
req = requests.get(f"{url}/encrypt_flag")
data = req.json()
c = data["ciphertext"]
r = requests.get(f"{url}/decrypt/{c}")
data = r.json()
p = data["plaintext"]
print(bytes.fromhex(p))
```
flag: crypto{bl0ck_c1ph3r5_4r3_f457_!}