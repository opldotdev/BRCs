#!/usr/bin/env python3
"""Verify the pinned Musashi raw transactions and Sigma issuer binding.

Python 3.8+ standard library only; no network access or SDK imports. This is a
fixture verifier, not a general inscription parser, script interpreter, SPV
client or ownership tracker. Raw hex files (or JSON-quoted hex) are required.
Public retrieval URLs are in 0185-musashi-evidence.json beside this script.
"""

import argparse
import hashlib
import json
from pathlib import Path


P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
MAP = b"1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).digest()


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    X, Y = b
    if x == X and (y + Y) % P == 0:
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if a == b
             else (Y - y) * pow(X - x, -1, P)) % P
    q = (slope * slope - x - X) % P
    return q, (slope * (x - q) - y) % P


def mul(k, point):
    require(k >= 0, "negative scalar")
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def address(public_key):
    payload = b"\x00" + hashlib.new("ripemd160", sha(public_key)).digest()
    payload += sha(sha(payload))[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value, encoded = int.from_bytes(payload, "big"), ""
    while value:
        value, digit = divmod(value, 58)
        encoded = alphabet[digit] + encoded
    return "1" * (len(payload) - len(payload.lstrip(b"\x00"))) + encoded


def recover(compact, message):
    require(len(compact) == 65 and 27 <= compact[0] <= 34, "compact signature")
    header = compact[0] - 27
    recovery, compressed = header & 3, bool(header & 4)
    r, s = int.from_bytes(compact[1:33], "big"), int.from_bytes(compact[33:], "big")
    require(1 <= r < N and 1 <= s < N, "signature scalar range")
    x = r + (recovery >> 1) * N
    require(x < P, "recovery x range")
    square = (x**3 + 7) % P
    y = pow(square, (P + 1) // 4, P)
    require(y * y % P == square, "recovery point is not on curve")
    if y & 1 != recovery & 1:
        y = P - y
    R = (x, y)
    require(mul(N, R) is None, "recovery point order")
    require(len(message) == 32, "Sigma message length")
    digest = sha(sha(b"\x18Bitcoin Signed Message:\n\x20" + message))
    z = int.from_bytes(digest, "big")
    Q = mul(pow(r, -1, N), add(mul(s, R), mul((-z) % N, G)))
    require(Q is not None, "recovered infinity")
    w = pow(s, -1, N)
    check = add(mul(z * w % N, G), mul(r * w % N, Q))
    require(check is not None and check[0] % N == r, "ECDSA verification")
    public_key = (bytes([2 + (Q[1] & 1)]) + Q[0].to_bytes(32, "big") if compressed
                  else b"\x04" + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))
    return public_key, digest


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        require(0 <= size <= len(self.data) - self.pos, "truncated bytes")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), "little")

    def compact_size(self):
        first = self.integer(1)
        if first < 253:
            return first
        size = {253: 2, 254: 4, 255: 8}[first]
        value = self.integer(size)
        require(value >= {253: 253, 254: 65536, 255: 4294967296}[first],
                "noncanonical CompactSize")
        return value


def transaction(raw):
    reader = Reader(raw)
    reader.take(4)  # version
    count = reader.compact_size()
    require(0 < count <= len(raw) // 41, "invalid legacy input count")
    inputs = []
    for _ in range(count):
        inputs.append((reader.take(32)[::-1], reader.integer(4)))
        reader.take(reader.compact_size())
        reader.take(4)  # sequence
    count = reader.compact_size()
    require(0 < count <= len(raw) // 9, "invalid output count")
    outputs = []
    for _ in range(count):
        value = reader.integer(8)
        outputs.append((value, reader.take(reader.compact_size())))
    reader.take(4)  # locktime
    require(reader.pos == len(raw), "trailing transaction bytes")
    return sha(sha(raw))[::-1].hex(), inputs, outputs


def script_ops(script):
    reader, result = Reader(script), []
    while reader.pos < len(script):
        start, opcode = reader.pos, reader.integer(1)
        size = opcode if 1 <= opcode <= 75 else 0
        if opcode in (76, 77, 78):
            size = reader.integer({76: 1, 77: 2, 78: 4}[opcode])
        data = reader.take(size) if opcode <= 78 else None
        result.append((start, opcode, data))
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def metadata_and_sigma(script):
    ops = script_ops(script)
    depth, tape_start, content_type = 0, None, None
    for i, (_, opcode, data) in enumerate(ops):
        if data == b"ord" and i >= 2 and ops[i - 1][1] == 99 and ops[i - 2][1] == 0:
            require(ops[i + 1][1] == 81, "fixture content-type tag")
            content_type = ops[i + 2][2].decode("utf8")
        if opcode in (99, 100):
            depth += 1
        elif opcode == 104:
            depth -= 1
            require(depth >= 0, "unbalanced fixture conditionals")
        elif opcode == 106 and depth == 0:
            tape_start = i + 1
            break
    require(tape_start is not None and content_type is not None, "fixture envelope/tape")
    segments, segment = [], []
    for op in ops[tape_start:]:
        require(op[2] is not None, "fixture tape must be push-only")
        if op[2] == b"|":
            segments.append(segment)
            segment = [op]  # retain exact separator byte offset
        else:
            segment.append(op)
    segments.append(segment)
    require(len(segments) == 2, "expected one MAP and one Sigma segment")
    fields = [op[2] for op in segments[0]]
    require(fields[:2] == [MAP, b"SET"] and len(fields) % 2 == 0, "MAP SET shape")
    values = unique_object([(fields[i].decode("utf8"), fields[i + 1].decode("utf8"))
                            for i in range(2, len(fields), 2)])
    sub = json.loads(values["subTypeData"], object_pairs_hook=unique_object)
    require(isinstance(sub, dict), "subTypeData object")
    sigma = segments[1]
    require(len(sigma) == 6 and [op[2] for op in sigma[1:3]] == [b"SIGMA", b"BSM"],
            "fixture Sigma shape")
    return values, sub, content_type, sigma[0][0], [op[2] for op in sigma[3:]]


def verify_record(record, path):
    text = path.read_text().strip()
    if text.startswith('"'):
        text = json.loads(text)
    raw = bytes.fromhex(text)
    txid, inputs, outputs = transaction(raw)
    require(txid == record["txid"], record["role"] + " txid mismatch")
    satoshis, script = outputs[record["outputIndex"]]
    require(satoshis == record["satoshis"] == 1, "one-satoshi output")
    require(len(script) == record["scriptLength"], "script length")
    values, sub, media, offset, (signer, compact, vin_bytes) = metadata_and_sigma(script)
    require(values == record["map"] and sub == record["subTypeData"], "pinned metadata")
    require(media == record["contentType"], "pinned media type")
    expected = record["sigma"][0]
    vin = int(vin_bytes.decode("ascii"))
    vin = record["outputIndex"] if vin == -1 else vin
    require(0 <= vin < len(inputs), "Sigma input range")
    txid_bytes, vout = inputs[vin]
    preimage = txid_bytes + vout.to_bytes(4, "little")
    input_hash, data_hash = sha(preimage), sha(script[:offset])
    message = sha(input_hash + data_hash)
    require(offset == expected["signedPrefixLength"] == expected["sigmaSeparatorOffset"],
            "signed prefix length")
    for actual, key in [(preimage.hex(), "inputBytesHex"), (input_hash.hex(), "inputHash"),
                        (data_hash.hex(), "signedPrefixSHA256"), (message.hex(), "messageHash"),
                        (compact.hex(), "compactSignatureHex"), (signer.decode(), "declaredSigner")]:
        require(actual == expected[key], key + " mismatch")
    key, digest = recover(compact, message)
    require(key.hex() == expected["recoveredPublicKey"], "recovered public key")
    require(address(key) == signer.decode() == expected["recoveredAddress"], "signer address")
    require(digest.hex() == expected["bitcoinSignedMessageDigest"], "BSM digest")
    return txid, values, sub, signer.decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-item", required=True, type=Path)
    parser.add_argument("--raw-root", required=True, type=Path)
    args = parser.parse_args()
    evidence = json.loads(Path(__file__).with_name("0185-musashi-evidence.json").read_text())
    records = {record["role"]: record for record in evidence["records"]}
    item = verify_record(records["item"], args.raw_item)
    root = verify_record(records["root"], args.raw_root)
    require(root[1]["type"] == item[1]["type"] == "ord", "MAP type")
    require(root[1]["subType"] == "collection" and item[1]["subType"] == "collectionItem",
            "collection roles")
    require(item[2]["collectionId"] == root[0] + "_0", "collection reference")
    require(item[3] == root[3], "issuer equality")
    print(json.dumps({"raw_transaction_ids": "verified", "signed_MAP_prefixes": "verified",
                      "issuer_binding": "verified", "signer": item[3],
                      "chain_inclusion": "not_checked", "full_membership": "not_checked",
                      "current_ownership": "not_checked"}, indent=2))


if __name__ == "__main__":
    main()
