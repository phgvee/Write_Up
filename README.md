#MAPLE CTF 2022 

#CRYPTO_ brsaby(50 pts)


![image](https://user-images.githubusercontent.com/97526925/187433520-60f80873-26a1-4782-92c7-bfbe9cb1a980.png)

Việc đầu tiên là mình sẽ tải file này về, đây là đoạn scripts mà mình nhận được : 
'''
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

msg = bytes_to_long(FLAG)
p = getPrime(512)
q = getPrime(512)
N = p*q
e = 0x10001
enc = pow(msg, e, N)
hint = p**4 - q**3

print(f"{N = }")
print(f"{e = }")
print(f"{enc = }")
print(f"{hint = }")
N = 134049493752540418773065530143076126635445393203564220282068096099004424462500237164471467694656029850418188898633676218589793310992660499303428013844428562884017060683631593831476483842609871002334562252352992475614866865974358629573630911411844296034168928705543095499675521713617474013653359243644060206273
e = 65537
enc = 110102068225857249266317472106969433365215711224747391469423595211113736904624336819727052620230568210114877696850912188601083627767033947343144894754967713943008865252845680364312307500261885582194931443807130970738278351511194280306132200450370953028936210150584164591049215506801271155664701637982648648103
hint = 20172108941900018394284473561352944005622395962339433571299361593905788672168045532232800087202397752219344139121724243795336720758440190310585711170413893436453612554118877290447992615675653923905848685604450760355869000618609981902108252359560311702189784994512308860998406787788757988995958832480986292341328962694760728098818022660328680140765730787944534645101122046301434298592063643437213380371824613660631584008711686240103416385845390125711005079231226631612790119628517438076962856020578250598417110996970171029663545716229258911304933901864735285384197017662727621049720992964441567484821110407612560423282
'''
Như một thói quen thì mình sẽ factor N ( mình hay dùng tool factordb) thì nó ko factor được vì N quá lớn. Sau khi đọc kĩ lại đoạn script thì mình phát hiện ra ở có đoạn hint ở phía dưới và hint = p**4 - q**3 , kết hợp với N = p*q thì mình có hệ phương trình 2 ẩn.Và vấn đề lúc này là làm sao để giải hệ phương trình khi hint là số vô cùng lớn.
Sau một lúc tìm hiểu về z3 ( search gg để xem z3 là gì nha ) thì mình viết một đoạn script nho nhỏ:
'''
from z3 import *
from Crypto.Util.number import inverse, long_to_bytes
x = Int('x')
y = Int('y')
n = 134049493752540418773065530143076126635445393203564220282068096099004424462500237164471467694656029850418188898633676218589793310992660499303428013844428562884017060683631593831476483842609871002334562252352992475614866865974358629573630911411844296034168928705543095499675521713617474013653359243644060206273
hint = 20172108941900018394284473561352944005622395962339433571299361593905788672168045532232800087202397752219344139121724243795336720758440190310585711170413893436453612554118877290447992615675653923905848685604450760355869000618609981902108252359560311702189784994512308860998406787788757988995958832480986292341328962694760728098818022660328680140765730787944534645101122046301434298592063643437213380371824613660631584008711686240103416385845390125711005079231226631612790119628517438076962856020578250598417110996970171029663545716229258911304933901864735285384197017662727621049720992964441567484821110407612560423282
solve(x*y == n, x**4 - y**3 == hint)
'''

![image](https://user-images.githubusercontent.com/97526925/187453934-78590bf5-3ab9-4a6c-b636-6ddcb6f0f849.png)

Taddaa sau khi có được p q thì mình dễ dàng tìm được message :
'''
from numbers import Real
from z3 import *
from Crypto.Util.number import inverse, long_to_bytes
n = 134049493752540418773065530143076126635445393203564220282068096099004424462500237164471467694656029850418188898633676218589793310992660499303428013844428562884017060683631593831476483842609871002334562252352992475614866865974358629573630911411844296034168928705543095499675521713617474013653359243644060206273
p = 11917573148183173444338385104784582231114229409447057112131253050235068806316496452352116287542988361044359262597423159386263430710183647113674868056755407
q = 11248052945492193606877386307812298309646455365482356576580845624056836046347518805927852646289457003475918197991787867864250859819603651806169306473552239
e = 65537
enc = 110102068225857249266317472106969433365215711224747391469423595211113736904624336819727052620230568210114877696850912188601083627767033947343144894754967713943008865252845680364312307500261885582194931443807130970738278351511194280306132200450370953028936210150584164591049215506801271155664701637982648648103
phi = (p-1)*(q-1)
d = inverse(e, phi)
msg = pow(enc, d, n)
print(long_to_bytes(msg))
'''
Và giờ thì mang flag đi nộp thôi :D
maple{s0lving_th3m_p3rf3ct_r000ts_1s_fun}




