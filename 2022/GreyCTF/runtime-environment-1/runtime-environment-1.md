# [RE] Runtime Environment 1

> GO and try to solve this basic challenge.
>
> FAQ: If you found the input leading to the challenge.txt you are on the right track
>
> MD5 (gogogo.tar.gz) = 5515f1c3eee00e4042bf7aba84bbec5c
>
> - rootkid
>
> **Attached Files**: binary, challenge.txt

Contents of `challenge.txt`:

```
GvVf+fHWz1tlOkHXUk3kz3bqh4UcFFwgDJmUDWxdDTTGzklgIJ+fXfHUh739+BUEbrmMzGoQOyDIFIz4GvTw+j--
```

First, I opened `binary` with IDA, revealing the `main_main` function which takes in an input, passes it to `main_Encode` and outputs the encoded string.

```c
// main.main
void __cdecl main_main()
{
  __int64 v0; // [rsp+10h] [rbp-98h]
  __int64 v1; // [rsp+18h] [rbp-90h]
  __int64 v2; // [rsp+20h] [rbp-88h]
  __int128 v3; // [rsp+20h] [rbp-88h]
  __int64 v4; // [rsp+30h] [rbp-78h]
  __int64 v5; // [rsp+38h] [rbp-70h]
  __int64 v6; // [rsp+40h] [rbp-68h]
  __int64 v7; // [rsp+48h] [rbp-60h]
  __int64 v8[4]; // [rsp+50h] [rbp-58h] BYREF
  __int64 v9; // [rsp+70h] [rbp-38h]
  __int64 *v10; // [rsp+78h] [rbp-30h]
  __int64 v11[2]; // [rsp+80h] [rbp-28h] BYREF
  __int64 v12[2]; // [rsp+90h] [rbp-18h] BYREF

  v10 = runtime_newobject(&RTYPE_string);
  v12[0] = &RTYPE__ptr_string;
  v12[1] = v10;
  fmt_Fscanln(&go_itab__ptr_os_File_comma_io_Reader, os_Stdin, v12, 1LL, 1LL);
  v7 = 4 * ((((((v10[1] + 2) * 0xAAAAAAAAAAAAAAABLL) >> 64) + v10[1] + 2) >> 1) - ((v10[1] + 2) >> 63));
  v9 = runtime_makeslice(&RTYPE_uint8, v7, v7);
  v1 = runtime_stringtoslicebyte(v8, *v10, v10[1]);
  main_Encode(v9, v7, v7, v1, v2);
  v3 = runtime_slicebytetostring(0LL, v4, v5, v6);
  v0 = runtime_convTstring(v3, *(&v3 + 1));
  v11[0] = &RTYPE_string;
  v11[1] = v0;
  fmt_Fprintln(&go_itab__ptr_os_File_comma_io_Writer, os_Stdout, v11, 1LL, 1LL);
}
```

Curious about the encoding function, I tried to analyze it but thought twice after seeing the code below:

```c
// main.Encode
__int64 __usercall main_Encode@<rax>(__int64 a1, unsigned __int64 a2, __int64 a3, __int64 a4, unsigned __int64 a5)
{
  unsigned __int64 v5; // rax
  unsigned __int64 v6; // rcx
  unsigned __int64 v7; // r10
  unsigned __int64 v8; // r11
  char v9; // r10
  char v10; // r10
  char v11; // r11
  char v12; // r10
  __int64 v13; // rbx
  unsigned __int64 v14; // rdx
  unsigned __int64 v15; // r8
  char v16; // dl
  unsigned __int64 v17; // rdx
  char v18; // r8
  char v20; // dl
  __int128 v21[4]; // [rsp+10h] [rbp-48h] BYREF

  qmemcpy(v21, "NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe", sizeof(v21));
  v5 = 0LL;
  v6 = 0LL;
  while ( v5 < 3 * (a5 / 3) )
  {
    if ( v5 >= a5 )
      runtime_panicIndex();
    if ( v5 + 1 >= a5 )
      runtime_panicIndex();
    if ( v5 + 2 >= a5 )
      runtime_panicIndex();
    v7 = (*(a4 + v5) << 16) | (*(a4 + v5 + 1) << 8) | *(v5 + a4 + 2);
    if ( v6 >= a2 )
      runtime_panicIndex();
    *(a1 + v6) = *(v21 + ((v7 >> 18) & 0x3F));
    v8 = v7;
    v9 = *(v21 + ((v7 >> 12) & 0x3F));
    if ( v6 + 1 >= a2 )
      runtime_panicIndex();
    *(v6 + a1 + 1) = v9;
    v10 = v8;
    v11 = *(v21 + ((v8 >> 6) & 0x3F));
    if ( v6 + 2 >= a2 )
      runtime_panicIndex();
    *(v6 + a1 + 2) = v11;
    v12 = *(v21 + (v10 & 0x3F));
    if ( v6 + 3 >= a2 )
      runtime_panicIndex();
    *(a1 + v6 + 3) = v12;
    v5 += 3LL;
    v6 += 4LL;
  }
  v13 = a5 - v5;
  if ( a5 == v5 )
    return a3;
  if ( v5 >= a5 )
    runtime_panicIndex();
  if ( v13 == 2 )
  {
    if ( v5 + 1 >= a5 )
      runtime_panicIndex();
    v14 = (*(a4 + v5) << 16) | (*(a4 + v5 + 1) << 8);
  }
  else
  {
    v14 = *(a4 + v5) << 16;
  }
  v15 = v14;
  v16 = *(v21 + ((v14 >> 18) & 0x3F));
  if ( v6 >= a2 )
    runtime_panicIndex();
  *(a1 + v6) = v16;
  v17 = v15;
  v18 = *(v21 + ((v15 >> 12) & 0x3F));
  if ( v6 + 1 >= a2 )
    runtime_panicIndex();
  *(v6 + a1 + 1) = v18;
  if ( v13 == 1 )
  {
    if ( v6 + 2 >= a2 )
      runtime_panicIndex();
    *(v6 + a1 + 2) = 45;
    if ( v6 + 3 >= a2 )
      runtime_panicIndex();
    *(v6 + a1 + 3) = 45;
  }
  else if ( v13 == 2 )
  {
    v20 = *(v21 + ((v17 >> 6) & 0x3F));
    if ( v6 + 2 >= a2 )
      runtime_panicIndex();
    *(v6 + a1 + 2) = v20;
    if ( v6 + 3 >= a2 )
      runtime_panicIndex();
    *(v6 + a1 + 3) = 45;
  }
  return a3;
}
```

Instead, I utilized black box testing in hopes of figuring out how the encoding works:

```bash
(base) rootyourfuture@kali:~$ /home/kali/Desktop/binary
grey{flaggy}
+fm3hkwdS1T4+f3t
(base) rootyourfuture@kali:~$ /home/kali/Desktop/binary
homerrr
s1tw+kmqnj--
(base) rootyourfuture@kali:~$ /home/kali/Desktop/binary
bigdawgg
Cd34+1Tf+yn-
```

| Input        | Output           |
| ------------ | ---------------- |
| grey{flaggy} | +fm3hkwdS1T4+f3t |
| homerrr      | s1tw+kmqnj--     |
| bigdawgg     | Cd34+1Tf+yn-     |

Comparing the outputs, I noticed that there were dashes at the end of some of them, which was similar to how `base64` encoding uses `==` as padding. This suggested to me that `main_Encode` was just base64 encoding utilizing an alternative character set. To validate my hypothesis, I referenced <a href="https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c">this stack overflow post</a>, which showed that base64 also utilizes bitwise shifts `>>` and `& 0x3F`.

Thus, I coded out the following python script, which maps the alternative character set that `binary` uses to the actual base64 character set before decoding it. Something to note is that the flag is actually encoded in multiple layers, so I had to repeat the decoding process multiple times.

```python
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
        b64_data = unk_to_b64(unk_data)
        ascii_data = b64_to_ascii(b64_data)
        print(ascii_data)

if __name__ == "__main__":
    main()

```

<u>Output</u>:

> X47gzutoh1zMUyWvU2zunI+kDBUGXfDQVuz+LFw7zUzIOduoS2zunb3dSI7gX1mf
> 6y+wOyxgzWmCV7tq6WDuV7tbCGY9+duWS2m9n7tqIfm9+4bw
> +fm3hkwRXBOr+TtBOTalOfm5n2OrOrOrOfu-
> grey{B4s3d_G0Ph3r_r333333}
