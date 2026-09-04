#!/usr/bin/env python3
"""Synthetic spec vectors; not a full chain, script, or interoperability verifier."""
import unittest
import math

MAX_LAT = math.degrees(math.atan(math.sinh(math.pi)))
def encode(lon, lat, z):
    n = 2**z
    lon = (lon+180) % 360-180
    lat = math.radians(max(-MAX_LAT, min(MAX_LAT, lat)))
    x = math.floor((lon+180)/360*n) % n
    y = max(0, min(n-1, math.floor((1-math.asinh(math.tan(lat))/math.pi)/2*n)))
    return x, y, ''.join(str(((x >> i)&1) + 2*((y >> i)&1)) for i in reversed(range(z)))


def bbox(q):
    x = y = 0
    for ch in q:
        d = int(ch); x = x*2+(d&1); y = y*2+(d>>1)
    n = 2**len(q)
    lat = lambda y: math.degrees(math.atan(math.sinh(math.pi*(1-2*y/n))))
    return x/n*360-180, lat(y+1), (x+1)/n*360-180, lat(y)


class Vectors(unittest.TestCase):
    def test_location_vectors(self):
        self.assertEqual(encode(-74.0445,40.6892,18), (77154,98583,'032010110301120232'))
        self.assertEqual(encode(-74.0445,40.6892,16), (19288,24645,'0320101103011202'))
        self.assertEqual(encode(0,0,1), (1,1,'3'))
    def test_bbox(self):
        self.assertEqual(tuple(round(x,6) for x in bbox('032010110301120232')),(-74.045105,40.688969,-74.043732,40.690010))
    def test_wrap_and_poles(self):
        for z in (1,18,30):
            self.assertEqual(encode(180,0,z),encode(-180,0,z))
            self.assertEqual(encode(-540,0,z),encode(-180,0,z))
            self.assertTrue(set(encode(70,90,z)[2]) <= set('01'))
            self.assertTrue(set(encode(70,-90,z)[2]) <= set('23'))
    def test_parents(self):
        for lon,lat in ((0,0),(-74.0445,40.6892),(140,-33)):
            for z in range(2,25):
                self.assertEqual(encode(lon,lat,z)[2][:-1],encode(lon,lat,z-1)[2])

if __name__ == '__main__':
    unittest.main()
