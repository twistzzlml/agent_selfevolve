# -*- coding: utf-8 -*-
"""在序列化流里定位锚点字节串：python findpat.py <file>"""
import sys

data = open(sys.argv[1], "rb").read()
pats = {
    "TC_STRING foo": b"\x74\x00\x03foo",
    "LazyMap": b"LazyMap",
    "TiedMapEntry": b"TiedMapEntry",
    "BadAttrValExp": b"BadAttributeValueExpException",
    "HashMap": b"java.util.HashMap",
    "Throwable": b"java.lang.Throwable",
    "StackTraceElement": b"StackTraceElement",
}
for name, p in pats.items():
    offs = []
    i = data.find(p)
    while i != -1:
        offs.append(i)
        i = data.find(p, i + 1)
    print("%-22s %s" % (name, offs))
