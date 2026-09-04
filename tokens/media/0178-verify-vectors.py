#!/usr/bin/env python3
"""Verify BRC-178 synthetic fixtures with Python 3's standard library.

This is a fixture checker, not a wallet, general Script interpreter, SPV verifier,
or production cryptographic implementation. Never use its public fixture keys
for funds. No SDK or network access is required.
"""
import copy
import hashlib
import json
import struct
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(value):
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b'\xfd' + struct.pack('<H', value)
    return b'\xfe' + struct.pack('<I', value)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        result = self.data[self.pos:self.pos + size]
        require(len(result) == size, 'truncated transaction')
        self.pos += size
        return result

    def number(self, size):
        return int.from_bytes(self.take(size), 'little')

    def count(self):
        value = self.number(1)
        return self.number({253: 2, 254: 4, 255: 8}[value]) if value >= 253 else value


def parse(raw):
    r = Reader(bytes.fromhex(raw))
    tx = {'version': r.take(4), 'inputs': [], 'outputs': []}
    for _ in range(r.count()):
        prevout = r.take(36)
        tx['inputs'].append({'prevout': prevout, 'script': r.take(r.count()), 'sequence': r.take(4)})
    for _ in range(r.count()):
        tx['outputs'].append({'satoshis': r.number(8), 'script': r.take(r.count())})
    tx['lockTime'] = r.take(4)
    require(r.pos == len(r.data), 'trailing transaction bytes')
    return tx


def output_bytes(output):
    script = output['script']
    return struct.pack('<Q', output['satoshis']) + varint(len(script)) + script


def pushes(script):
    r, result = Reader(script), []
    while r.pos < len(script):
        op = r.number(1)
        if 1 <= op <= 75:
            result.append(r.take(op))
        elif op in (76, 77, 78):
            result.append(r.take(r.number({76: 1, 77: 2, 78: 4}[op])))
    return result


# Independent secp256k1 verification, for fixed public fixtures only.
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, P) if a == b else (v-y)*pow(u-x, -1, P)) % P
    z = (slope*slope-x-u) % P
    return z, (slope*(x-z)-y) % P


def mul(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def verify_signature(tx, index, source):
    parts = pushes(tx['inputs'][index]['script'])
    require(len(parts) == 2, 'fixture requires P2PKH unlock')
    sig, pub = parts
    require(sig[-1] == 0x41, 'prohibited sighash')
    der = Reader(sig[:-1])
    require(der.number(1) == 0x30 and der.number(1) == len(sig)-3, 'bad DER')
    require(der.number(1) == 2, 'bad r')
    r = int.from_bytes(der.take(der.number(1)), 'big')
    require(der.number(1) == 2, 'bad s')
    s = int.from_bytes(der.take(der.number(1)), 'big')
    require(0 < r < N and 0 < s <= N//2, 'invalid signature scalar')
    require(len(pub) == 33 and pub[0] in (2, 3), 'bad public key')
    x = int.from_bytes(pub[1:], 'big')
    y = pow((x*x*x+7) % P, (P+1)//4, P)
    if y % 2 != pub[0] % 2:
        y = P-y
    require(x < P and y*y % P == (x*x*x+7) % P, 'off-curve key')
    key_hash = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    require(b'\x76\xa9\x14'+key_hash+b'\x88\xac' in source['script'], 'wrong source owner')
    inp = tx['inputs'][index]
    script = source['script']
    preimage = (tx['version'] + hash256(b''.join(i['prevout'] for i in tx['inputs']))
                + hash256(b''.join(i['sequence'] for i in tx['inputs']))
                + inp['prevout'] + varint(len(script)) + script
                + struct.pack('<Q', source['satoshis']) + inp['sequence']
                + hash256(b''.join(output_bytes(o) for o in tx['outputs']))
                + tx['lockTime'] + struct.pack('<I', 0x41))
    z = int.from_bytes(hash256(preimage), 'big')
    w = pow(s, -1, N)
    point = add(mul(z*w % N, G), mul(r*w % N, (x, y)))
    require(point is not None and point[0] % N == r, 'signature does not commit to candidate')


def verify_transaction(tx, sources, expected):
    resolved = []
    for inp in tx['inputs']:
        txid = inp['prevout'][:32][::-1].hex()
        index = int.from_bytes(inp['prevout'][32:], 'little')
        resolved.append(sources[txid]['outputs'][index])
    require(sum(o['satoshis'] for o in resolved)-sum(o['satoshis'] for o in tx['outputs']) == expected['feeSatoshis'], 'fee mismatch')
    for route in expected['ordinalRoutes']:
        i, o = route['input'], route['output']
        require(resolved[i]['satoshis'] == tx['outputs'][o]['satoshis'] == 1, 'not a one-satoshi route')
        require(sum(x['satoshis'] for x in resolved[:i]) == sum(x['satoshis'] for x in tx['outputs'][:o]), 'ordinal route mismatch')
    for token in expected['tokenConservation']:
        totals = []
        for entries, outputs in [(token['inputs'], resolved), (token['outputs'], tx['outputs'])]:
            total = 0
            for entry in entries:
                payloads = [json.loads(v) for v in pushes(outputs[entry['index']]['script']) if v.startswith(b'{')]
                require(len(payloads) == 1, 'token payload missing')
                data = payloads[0]
                require(data['op'] == 'transfer' and data['id'] == token['tokenId'] and data['amt'] == entry['amount'], 'token mismatch')
                total += int(data['amt'])
            totals.append(total)
        require(totals[0] == totals[1], 'token conservation mismatch')
    for i, source in enumerate(resolved):
        verify_signature(tx, i, source)


def verify_trace(trace):
    state = dict(revision=1, ready=dict(alice=False, bob=False), phase='negotiating', attempts=0)
    sequences, released = dict(alice=0, bob=0), False
    for step in trace['steps']:
        op = step['operation']
        kind = op['kind']
        if kind in ('ready', 'edit'):
            actor = op['actor']
            if state['phase'] == 'negotiating' and op['revision'] == state['revision'] and op['sequence'] > sequences[actor]:
                sequences[actor] = op['sequence']
                if kind == 'edit':
                    state['revision'] += 1
                    state['ready'] = dict(alice=False, bob=False)
                else:
                    state['ready'][actor] = op['ready']
                    if all(state['ready'].values()):
                        state['phase'] = 'attempting'
                        state['attempts'] += 1
        elif kind == 'signature-released':
            released = True
        elif kind == 'failure' and released:
            state['phase'] = 'reconciling'
        elif kind in ('failure', 'candidate-invalidated'):
            state['phase'] = 'negotiating'
            state['revision'] += 1
            state['ready'] = dict(alice=False, bob=False)
            released = False
        elif kind != 'timeout':
            raise ValueError('unknown event')
        require(state == step['expected'], f"{trace['id']}: {op} produced {state}")


def main():
    data = json.loads(Path(__file__).with_name('0178-exchange-vectors.json').read_text())
    for trace in data['stateTraces']:
        verify_trace(trace)
    negatives = 0
    for vector in data['transactions']:
        require(hash256(bytes.fromhex(vector['rawTransaction']))[::-1].hex() == vector['txid'], 'txid mismatch')
        sources = {}
        for src in vector['sources']:
            require(hash256(bytes.fromhex(src['rawTransaction']))[::-1].hex() == src['txid'], 'source txid mismatch')
            sources[src['txid']] = parse(src['rawTransaction'])
        tx = parse(vector['rawTransaction'])
        require(int.from_bytes(tx['version'], 'little') == vector['expected']['version'], 'version mismatch')
        require(int.from_bytes(tx['lockTime'], 'little') == vector['expected']['lockTime'], 'lock time mismatch')
        verify_transaction(tx, sources, vector['expected'])
        for case in vector['negativeCases']:
            changed = copy.deepcopy(tx)
            if case == 'changed-lock-time':
                changed['lockTime'] = struct.pack('<I', 1)
            elif case == 'changed-output-amount':
                changed['outputs'][1]['satoshis'] += 1
            elif case == 'prohibited-sighash':
                script = bytearray(changed['inputs'][0]['script'])
                script[script[0]] = 0xc1
                changed['inputs'][0]['script'] = bytes(script)
            elif case == 'reordered-ordinal-inputs':
                changed['inputs'][0], changed['inputs'][-1] = changed['inputs'][-1], changed['inputs'][0]
            else:
                raise ValueError('unknown negative case')
            try:
                verify_transaction(changed, sources, vector['expected'])
            except ValueError:
                negatives += 1
            else:
                raise ValueError('accepted negative case: '+case)
    print(f"PASS: {len(data['stateTraces'])} readiness traces, {len(data['transactions'])} signed transactions, {negatives} rejection cases")


if __name__ == '__main__':
    main()
