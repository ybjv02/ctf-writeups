"""
References: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
"""

import base64

unk = "NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe-"
b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

def unk_to_b64(s):
    res = ""
    for i in range(len(s)):
        pos = unk.find(s[i])
        res += b64[pos]
    return res

def b64_to_ascii(s):
    return base64.b64decode(s.encode()).decode()

def main():
    with open("challenge.txt", "r") as f:
        unk_data = f.read()
        while True:
            b64_data = unk_to_b64(unk_data)
            ascii_data = b64_to_ascii(b64_data)
            print(ascii_data)
            unk_data = ascii_data

if __name__ == "__main__":
    main()
