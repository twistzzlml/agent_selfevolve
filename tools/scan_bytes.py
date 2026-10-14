# -*- coding: utf-8 -*-
"""扫描序列化流中的 urlencoded 危险字节（& = % +）与高字节占比。"""
import sys

data = open(sys.argv[1], "rb").read()
print("len", len(data))
for b in (0x26, 0x3D, 0x25, 0x2B):
    offs = [i for i, c in enumerate(data) if c == b]
    print(hex(b), len(offs), offs[:12])
