***BASE_64***

#crypto

Bài này cho mình một file b64.py 
~~~
b64 = {
    "000000": "/",
    "000001": "+",
    "000010": "0",
    "000011": "1",
    "000100": "2",
    "000101": "3",
    "000110": "4",
    "000111": "5",
    "001000": "6",
    "001001": "7",
    "001010": "8",
    "001011": "9",
    "001100": "a",
    "001101": "b",
    "001110": "c",
    "001111": "d",
    "010000": "e",
    "010001": "f",
    "010010": "g",
    "010011": "h",
    "010100": "i",
    "010101": "j",
    "010110": "k",
    "010111": "l",
    "011000": "m",
    "011001": "n",
    "011010": "o",
    "011011": "p",
    "011100": "q",
    "011101": "r",
    "011110": "s",
    "011111": "t",
    "100000": "u",
    "100001": "v",
    "100010": "w",
    "100011": "x",
    "100100": "y",
    "100101": "z",
    "100110": "A",
    "100111": "B",
    "101000": "C",
    "101001": "D",
    "101010": "E",
    "101011": "F",
    "101100": "G",
    "101101": "H",
    "101110": "I",
    "101111": "J",
    "110000": "K",
    "110001": "L",
    "110010": "M",
    "110011": "N",
    "110100": "O",
    "110101": "P",
    "110110": "Q",
    "110111": "R",
    "111000": "S",
    "111001": "T",
    "111010": "U",
    "111011": "V",
    "111100": "W",
    "111101": "X",
    "111110": "Y",
    "111111": "Z",
}


def encode(string):
    s = ""
    for i in string:
        s += bin(ord(i))[2:].zfill(8)
       
    pad = ""
    if len(s) % 6 == 4:
        pad = "="
        s += "11"
    elif len(s) % 6 == 2:
        pad = "=="
        s += "1111"
    
    ret = ""
    for i in range(0,len(s),6):
        ret += b64[s[i:i+6]]
    return ret+pad
    

# from secret import FLAG
# print(encode(FLAG))

# gOP+sRaKphbtmRjNr1+HlObgkl+Oa5R=
~~~
Sau khi đọc sourcecode thì mình đã hiểu ra cách encode :
   - plaintext ban đầu sẽ chuyển về mã Ascii, sau đó từ mã Ascii chuyển về nhị phân với đủ 8 bit
   - tiếp theo sẽ check xem nếu độ dài của chuỗi chia dư cho 6 == 4 thì sẽ cộng thêm "11" còn nếu chia dư cho 6 ==2 thì sẽ cộng thêm "1111"
   - cuối cùng là dựa vào json phía trên để chuyển thành cipher ( các cậu chú ý phần pad nữa nha)
   
Và Cipher của đề :  gOP+sRaKphbtmRjNr1+HlObgkl+Oa5R=

Khi đã hiểu cách encode thì giờ chúng ta chỉ cần viết script để decode thui :

~~~
from multiprocessing import Value


b64 = {
    "000000": "/",
    "000001": "+",
    "000010": "0",
    "000011": "1",
    "000100": "2",
    "000101": "3",
    "000110": "4",
    "000111": "5",
    "001000": "6",
    "001001": "7",
    "001010": "8",
    "001011": "9",
    "001100": "a",
    "001101": "b",
    "001110": "c",
    "001111": "d",
    "010000": "e",
    "010001": "f",
    "010010": "g",
    "010011": "h",
    "010100": "i",
    "010101": "j",
    "010110": "k",
    "010111": "l",
    "011000": "m",
    "011001": "n",
    "011010": "o",
    "011011": "p",
    "011100": "q",
    "011101": "r",
    "011110": "s",
    "011111": "t",
    "100000": "u",
    "100001": "v",
    "100010": "w",
    "100011": "x",
    "100100": "y",
    "100101": "z",
    "100110": "A",
    "100111": "B",
    "101000": "C",
    "101001": "D",
    "101010": "E",
    "101011": "F",
    "101100": "G",
    "101101": "H",
    "101110": "I",
    "101111": "J",
    "110000": "K",
    "110001": "L",
    "110010": "M",
    "110011": "N",
    "110100": "O",
    "110101": "P",
    "110110": "Q",
    "110111": "R",
    "111000": "S",
    "111001": "T",
    "111010": "U",
    "111011": "V",
    "111100": "W",
    "111101": "X",
    "111110": "Y",
    "111111": "Z",
}
def key(val):
    for key, value in b64.items():
        if(val==value):
            return key

def binary_to_text(s):
    c =" "
    for i in range(len(s)//8):
        c+=chr(int(s[i*8:i*8+8],2))   
    return c

def decode(string):
    s = ""
    for i in string:
        s += key(i)
    res = binary_to_text(s)
    return res 
FLAG = "gOP+sRaKphbtmRjNr1+HlObgkl+Oa5R"
print(decode(FLAG))
~~~
Nói sơ về cái script của mình nha:
  - mình sẽ chuyển flag về dạng binary dựa trên cái json
  - từ binary mình chuyển sang text ( Unicode)
  
Tadda cứ run code là mình sẽ có đc FLAG = KMA{s0m3_cust0m_CRYpt0}
<33
