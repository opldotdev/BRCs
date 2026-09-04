#!/usr/bin/env python3
"""Synthetic spec vectors; not a full chain, script, or interoperability verifier."""
import unittest
import math

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
if __name__ == '__main__':
    unittest.main()
