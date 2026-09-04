#!/usr/bin/env python3
"""BRC-513 primitive-only fixture: NOT a security or interoperability test."""
import hashlib
import hmac
H = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
r = bytes(range(128))
prk = H(bytes(32), r)
t1 = H(prk, b'bsv group message keys\x01')
t2 = H(prk, t1 + b'bsv group message keys\x02')
assert t1.hex() == '95806396f223a283858523238b9011ac6253130bd897e405601470da3e28fb79'
assert t2[:12].hex() == 'd204791ff5204d1cc5fa2e59'
parts = [r[i:i+32] for i in range(0,128,32)]
for i in range(1,257):
    j = 0 if i % 2**24 == 0 else 1 if i % 2**16 == 0 else 2 if i % 256 == 0 else 3
    old = parts[j]
    parts[j:] = [H(old, bytes([k])) for k in range(j,4)]
assert hashlib.sha256(b''.join(parts)).hexdigest() == 'adb1b84e4b3c23c90fff5ded6e8fcfcd0a6210fd6c5c9d2cf463a93c2b7f3985'
print('PASS: group HKDF and ratchet 256 boundary only; no AEAD/wire/membership assertions')
