#!/usr/bin/env python3
"""Synthetic raw Script and state-profile vectors; caller must validate the selected chain. Not a production resolver or independent implementation."""
import unittest
import re
import json
from pathlib import Path

def fold(revisions):
    suppressed = set()
    for i in range(len(revisions)-1, -1, -1):
        if i not in suppressed:
            for cmd in revisions[i]:
                if cmd[0] == 'CLEAR':
                    suppressed.update(j for j in cmd[1:] if 0 <= j < i)
    state = {}
    for i, commands in enumerate(revisions):
        if i in suppressed:
            continue
        for cmd in commands:
            op, *args = cmd
            if op == 'SET':
                for j in range(0, len(args)-1, 2):
                    state[args[j]] = [args[j+1]]
            elif op == 'ADD':
                key, *values = args
                for value in values:
                    if value not in state.setdefault(key, []):
                        state[key].append(value)
            elif op == 'REMOVE':
                for key in args:
                    state.pop(key, None)
            elif op == 'DELETE':
                key, *values = args
                remaining = [v for v in state.get(key, []) if v not in values]
                if remaining:
                    state[key] = remaining
                else:
                    state.pop(key, None)
    return state


PREFIX=b'1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5'
def commands(script,earlier):
    """Parse the new profile's bounded, push-only post-OP_RETURN carrier."""
    pushes=[];i=0;depth=0;carrier=False
    while i<len(script):
        op=script[i];i+=1;value=None
        if op<=75:n=op
        elif op in (76,77,78):
            size={76:1,77:2,78:4}[op]
            if i+size>len(script):raise ValueError('truncated length')
            n=int.from_bytes(script[i:i+size],'little');i+=size
        else:n=None
        if n is not None:
            if i+n>len(script):raise ValueError('truncated push')
            value=script[i:i+n];i+=n
        if carrier:
            if value is None:raise ValueError('non-push carrier')
            pushes.append(value)
        elif value is None:
            if op in (99,100):depth+=1
            elif op==103 and depth==0:raise ValueError('unmatched ELSE')
            elif op==104:
                if depth==0:raise ValueError('unmatched ENDIF')
                depth-=1
            elif op==106 and depth==0:carrier=True
    if depth:raise ValueError('unclosed conditional')
    segments=[[]]
    for value in pushes:
        if value==b'|':segments.append([])
        else:segments[-1].append(value)
    result=[]
    for seg in segments:
        if not seg or seg[0]!=PREFIX:continue
        chunks=[[]]
        for value in seg[1:]:
            if value==b':::':chunks.append([])
            else:chunks[-1].append(value)
        # SELECT is a command-prefix token, never a scan of data arguments.
        if sum(bool(c) and c[0]==b'SELECT' for c in chunks)>1:continue
        applicable=True;explicit=False
        for c in chunks:
            if not c:continue
            if c[0]==b'SELECT':
                explicit=True
                if len(c)<3 or not re.fullmatch(b'[0-9a-fA-F]{64}',c[1]):
                    applicable=False;continue
                applicable=c[1].lower() in earlier;c=c[2:]
                if c[0]==b'SELECT':applicable=False;continue
            if not applicable:continue
            op,*args=c
            if op==b'SET':result.append(('SET',*args))
            elif op in (b'ADD',b'DELETE') and len(args)>=2:
                if op==b'ADD' or explicit:result.append((op.decode(),*args))
            elif op==b'REMOVE' and args and explicit:result.append(('REMOVE',*args))
            elif op==b'CLEAR' and args:
                targets=[earlier[a.lower()] for a in args if re.fullmatch(b'[0-9a-fA-F]{64}',a) and a.lower() in earlier]
                result.append(('CLEAR',*targets))
    return result

def resolve(records):
    # Caller supplies an already validated, branch-specific complete chain.
    # None explicitly models unavailable ancestry/output bytes.
    earlier={};parsed=[]
    for txid,script in records:
        if script is None:raise ValueError('incomplete')
        if txid in earlier:raise ValueError('repeated transaction in chain')
        parsed.append(commands(script,earlier));earlier[txid]=len(parsed)-1
    return fold(parsed)
def push(b):
    n=len(b)
    return (bytes([n]) if n<76 else b'\x4c'+bytes([n]))+b

def carrier(*fields):return b'\x00\x6a'+b''.join(push(f) for f in fields)
T=[('%064x'%i).encode() for i in range(1,10)]

class Vectors(unittest.TestCase):
    def test_state_example_and_clear(self):
        revisions = [ [('SET','name','Genesis'),('ADD','tags','a','b')], [('ADD','tags','b','c')], [('DELETE','tags','a'),('SET','title','Renamed')], [('CLEAR',2)] ]
        self.assertEqual(fold(revisions[:3]), {'name':['Genesis'],'tags':['b','c'],'title':['Renamed']})
        self.assertEqual(fold(revisions), {'name':['Genesis'],'tags':['a','b','c']})
    def test_clear_of_clear(self):
        self.assertEqual(fold([[('SET','x','a')],[('CLEAR',0)],[('CLEAR',1)]]), {'x':['a']})
    def test_two_clearers(self):
        revs = [[('SET','x','a')],[('CLEAR',0)],[('CLEAR',0)],[('CLEAR',2)]]
        self.assertEqual(fold(revs), {})
        self.assertEqual(fold(revs+[[('CLEAR',1)]]), {'x':['a']})
    def test_partial_set_and_lists(self):
        self.assertEqual(fold([[('SET','x','a','x','b','trailing')],[],[('ADD','x','b','B')]]), {'x':['b','B']})
        self.assertEqual(fold([[('ADD','x','a','b')],[('DELETE','x','a','b')]]), {})

    def test_raw_context_and_pipeline(self):
        a=carrier(PREFIX,b'SET',b'x',b'a')
        b=carrier(PREFIX,b'SELECT',T[0],b'ADD',b'x',b'b',b':::',b'DELETE',b'x',b'a',b'|',PREFIX,b'REMOVE',b'x',b':::',b'SET',b'y',b'z')
        self.assertEqual(resolve([(T[0],a),(T[1],b)]),{b'x':[b'b'],b'y':[b'z']})
    def test_other_and_malformed_select(self):
        for target in (T[8],b'bad'):
            b=carrier(PREFIX,b'SELECT',target,b'SET',b'x',b'bad',b':::',b'CLEAR',T[0],b':::',b'SET',b'y',b'bad')
            self.assertEqual(resolve([(T[0],carrier(PREFIX,b'SET',b'x',b'a')),(T[1],b)]),{b'x':[b'a']})
    def test_multiple_select_rolls_back_segment(self):
        b=carrier(PREFIX,b'CLEAR',T[0],b':::',b'SELECT',T[0],b'SET',b'y',b'bad',b':::',b'SELECT',T[0],b'SET',b'z',b'bad')
        self.assertEqual(resolve([(T[0],carrier(PREFIX,b'SET',b'x',b'a')),(T[1],b)]),{b'x':[b'a']})
    def test_byte_preservation_partial_commands(self):
        b=carrier(PREFIX,b'SET',b'x',b'\0',b'odd',b':::',b'ADD',b'x',b'',b' ',b'\xff',b'\0',b':::',b'BOGUS',b'x',b':::',b'ADD',b'empty')
        self.assertEqual(resolve([(T[0],b)]),{b'x':[b'\0',b'',b' ',b'\xff']})
    def test_raw_clear_restores_and_empty_link(self):
        a=carrier(PREFIX,b'SET',b'x',b'a')
        b=carrier(PREFIX,b'CLEAR',T[0]);c=carrier(PREFIX,b'CLEAR',T[1])
        self.assertEqual(resolve([(T[0],a),(T[1],b),(T[2],c),(T[3],b'\x51')]),{b'x':[b'a']})
    def test_no_false_carrier(self):
        trap=carrier(PREFIX,b'SET',b'x',b'bad')
        self.assertEqual(resolve([(T[0],push(trap)+b'\x51')]),{})
        self.assertEqual(resolve([(T[0],b'\x00\x63'+trap+b'\x68\x51')]),{})
        # A push's payload cannot open a protocol segment.
        self.assertEqual(resolve([(T[0],carrier(b'other',PREFIX,b'SET',b'x',b'bad'))]),{})
    def test_script_errors_and_incomplete(self):
        for raw in (b'\x00\x6a\x4c',b'\x00\x6a\x03a',b'\x00\x6a\x76',b'\x63',b'\x67',b'\x67'+carrier(PREFIX,b'SET',b'x',b'a'),None):
            with self.assertRaises(ValueError):resolve([(T[0],raw)])
    def test_branch_isolation(self):
        root=(T[0],carrier(PREFIX,b'SET',b'x',b'a'))
        left=(T[1],carrier(PREFIX,b'SET',b'x',b'b'))
        right=(T[2],carrier(PREFIX,b'SET',b'x',b'c'))
        self.assertEqual(resolve([root,left]),{b'x':[b'b']})
        self.assertEqual(resolve([root,right]),{b'x':[b'c']})

if __name__ == '__main__':
    unittest.main()
