#!/usr/bin/env python3
"""Independent hash-only BRC-511 fixtures; not signed transaction/state tests."""
import hashlib
H = lambda b: hashlib.sha256(b).digest()
address = b'1WffojxvgpQBmUTigoss7VUdfN45JiiRK'
h = H(address)
r = hashlib.new('ripemd160', h).digest()
assert h.hex() == 'c38bc59316de9783b5f7a8ba19bc5d442f6c9b0988c48a241d1c58a1f4e9ae19'
assert r.hex() == 'ba64f76a5b8dc4b8938b52b3e9c6c237c203913d'
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n, result = int.from_bytes(r, 'big'), ''
while n:
    n, digit = divmod(n, 58)
    result = alphabet[digit] + result
result = '1' * (len(r)-len(r.lstrip(b'\x00'))) + result
assert result == '3bcbMuLoBYTYTXKjthzjwiWze4Eg'
u = b'urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa'
ah = H(u).hex()
assert ah == 'b17c8e606afcf0d8dca65bdf8f33d275239438116557980203c82b0fae259838'
attest = ('urn:bap:attest:' + ah + ':' + result).encode()
assert H(attest).hex() == '31a05fd610cf3902e3ff1effd8fe3a775ad15db6a00a4ed47406ce705f105f73'
assert H(attest) != H(attest.replace(b'urn:bap:attest:', b'urn:bap:id:attest:'))
assert H(u) != H(u+b'\n')
print('PASS: BAP UTF-8 root/Base58 and exact URN hashes; newline/alternate scheme differ')
