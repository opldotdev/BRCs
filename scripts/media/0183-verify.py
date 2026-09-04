#!/usr/bin/env python3
"""Independent Python standard-library check of the BRC-504 BSM vector.

No dependencies. This tests cryptographic preimages and ECDSA, not a Sigma parser.
"""
import hashlib

H = lambda value: hashlib.sha256(value).digest()
txid = bytes.fromhex('9a1b3c5d7e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293')
prefix = bytes.fromhex('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac6a223150755161374b36324d694b43747373534c4b79316b683536575755374d745552350353455403617070097369676d6164656d6f')
ih = H(txid + (1).to_bytes(4, 'little'))
dh = H(prefix)
m = H(ih + dh)
assert ih.hex() == '33dd9d77bce09fc606a55046fe025776b73f2f2698937a6516fce470d7d499cd'
assert dh.hex() == '1777f397d3e9794036927163453d01c3fbea8437d1849f6604a62b4af3af2037'
assert m.hex() == 'b4d42dcaccfa952caae539fe9fe5d0111b5612bc92ddc8c11dad54ff5ce4349c'
sig = bytes.fromhex('1fffc4adbaf4b3e426d49f5ec571624f5dcf8c75a059f5a341e7740323ad513b8c5a86c49554f4e3432f66b9ff0e71d2560587a6fd7b5ec82ed7947036f6438a68')
p = 2**256 - 2**32 - 977
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)

def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    X, Y = b
    if x == X and (y + Y) % p == 0: return None
    slope = ((3*x*x)*pow(2*y, -1, p) if a == b else (Y-y)*pow(X-x, -1, p)) % p
    q = (slope*slope-x-X) % p
    return q, (slope*(x-q)-y) % p

def mul(k, a):
    q = None
    while k:
        if k & 1: q = add(q, a)
        a = add(a, a)
        k >>= 1
    return q

def verify(message):
    z = int.from_bytes(H(H(b'\x18Bitcoin Signed Message:\n\x20' + message)), 'big')
    r, s = int.from_bytes(sig[1:33], 'big'), int.from_bytes(sig[33:], 'big')
    assert 1 <= r < n and 1 <= s < n
    w = pow(s, -1, n)
    R = add(mul(z*w % n, G), mul(r*w % n, G))
    return R is not None and R[0] % n == r

assert len(sig) == 65 and sig[0] == 31
assert verify(m)
assert not verify(H(H(txid[::-1] + (1).to_bytes(4, 'little')) + dh))
assert not verify(H(m))
assert not verify(H(ih + H(prefix + b'\x00')))
# An identical outpoint/prefix remains valid regardless of unsigned tx fields.
assert verify(H(ih + dh))
print('PASS: Sigma BSM hashes, ECDSA, changed txid order/double-hash/prefix negatives')
