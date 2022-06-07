# [Crypto] Close Enough

> **Author**: TheMythologist
>
> My prof mentioned something about not using primes that are close to each other in RSA, but it's close enough, isn't it?
>
> Ciphertext is `4881495507745813082308282986718149515999022572229780274224400469722585868147852608187509420010185039618775981404400401792885121498931245511345550975906095728230775307758109150488484338848321930294974674504775451613333664851564381516108124030753196722125755223318280818682830523620259537479611172718588812979116127220273108594966911232629219195957347063537672749158765130948724281974252007489981278474243333628204092770981850816536671234821284093955702677837464584916991535090769911997642606614464990834915992346639919961494157328623213393722370119570740146804362651976343633725091450303521253550650219753876236656017`
>
> For beginners: https://ctf101.org/cryptography/what-is-rsa/
>
> MD5: `35601e92f6bc17e36bc042ba30f3ebc4`
>
> **Attached Files**: encrypt.py, key

Opening `encrypt.py` shows that the generated primes are close to one another, which makes the RSA decryption vulnerable to [Fermat's Factorization Method](https://facthacks.cr.yp.to/fermat.html).

```python
from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.PublicKey import RSA
from secret import flag, getNextPrime

p = getPrime(1024)
q = getNextPrime(p)
n = p * q
e = 65537

key = RSA.construct((n, e)).export_key().decode()

with open("key", "w") as f:
    f.write(key)

m = bytes_to_long(flag.encode())
c = pow(m, e, n)
print(f"c = {c}")
```

Opening `key` reveals that the RSA public key is encoded as base64 in the [ASN.1 format](https://www.cryptosys.net/pki/rsakeyformats.html), which syntax is explained [here](https://datatracker.ietf.org/doc/html/rfc2313#section-7.2). Using an [ASN.1 parser](https://lapo.it/asn1js), I am able to retrieve the key as a decimal number.

> -----BEGIN PUBLIC KEY-----
> MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBKS/xOueb8SyhYskLwm2DT
> hofceXDq73pNlu7CAwf1rTYFfYUgbiaKqkOfyTDurLOVXhWnwcmCRo9HwUUEyHG3
> swXS5OoSGmHHplMv8crTLlY+/hCpEFnLSPDcnl7HI7a/oprKpCgeiZOphEiIhm8x
> UQqivWqZvGzeV9EfjeaAaPlztu3nuRyfccMjqozreU20f8SNSa9wD6vKqtAgvjv3
> VapvlRVHRfPvlWCr09VE8W1qzdWvk0XWnyihd+3ssCgKBXpirylAT1WWZk6d3Ryq
> bh7biTpeVqzovEFZpQrm2T8Ym6TMRkbImLo9ObEOyVvP3TyUOUtalgDh1iaqHWkn
> AgMBAAE=
> -----END PUBLIC KEY-----

Afterwards, we obtain `p` & `q` via a [Python script](https://stackoverflow.com/questions/20464561/fermat-factorisation-with-python) based on Fermat Factorization found online, and `d` using the [Extended Euclidean algorithm](https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm). With this information, we can now crack the flag!

```python
"""
References:
https://stackoverflow.com/questions/20464561/fermat-factorisation-with-python
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
"""

n = 9379104451666902807254251547664494589376537004464676565187690588653871658978822987097064298936295147221139510534805502109113119601614394205797875059439905610480321353589582133110727481084808437441842912190040256221115163284631623589000119654843098091251164625806009940056025960835406998838387521455069967004404011645684521669329210152867128697650117219793408414423485717757224152576433432244378386973038733036305783601847652110678653741642215483011184789551861027169721217226927325340419066252945574407810391883801428118671134092909741227928016626842719456736068380990227433485001024796590524675348060787126908578087
e = 65537
c = 4881495507745813082308282986718149515999022572229780274224400469722585868147852608187509420010185039618775981404400401792885121498931245511345550975906095728230775307758109150488484338848321930294974674504775451613333664851564381516108124030753196722125755223318280818682830523620259537479611172718588812979116127220273108594966911232629219195957347063537672749158765130948724281974252007489981278474243333628204092770981850816536671234821284093955702677837464584916991535090769911997642606614464990834915992346639919961494157328623213393722370119570740146804362651976343633725091450303521253550650219753876236656017

def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

def fermat(n, verbose=False):
    a = isqrt(n) # int(ceil(n**0.5))
    b2 = a*a - n
    b = isqrt(n) # int(b2**0.5)
    count = 0
    while b*b != b2:
        if verbose:
            print('Trying: a=%s b2=%s b=%s' % (a, b2, b))
        a = a + 1
        b2 = a*a - n
        b = isqrt(b2) # int(b2**0.5)
        count += 1
    p=a+b
    q=a-b
    assert n == p * q
    return p, q
  
# Find p & q
p, q = fermat(n)

# Define phi
phi = ((p-1) * (q-1))

# Find d
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def mulinv(a, b):
    """return x such that (x * a) % b == 1"""  #(d * e) % phi == 1
    g, x, _ = xgcd(a, b)
    if g == 1:
        return x % b

d = mulinv(e, phi)

# Find m
print(hex(pow(c,d,n)))
```

Flag: SEE{i_love_really_secure_algorithms_b5c0b187fe309af0f4d35982fd961d7e}