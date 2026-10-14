# -*- coding: utf-8 -*-
"""打印危险字节上下文：python ctx.py <file> <offset>"""
import sys

data = open(sys.argv[1], "rb").read()
off = int(sys.argv[2])
lo, hi = max(0, off - 40), min(len(data), off + 40)
for i in range(lo, hi):
    b = data[i]
    mark = " <-- HERE" if i == off else ""
    ch = chr(b) if 32 <= b < 127 else "."
    print("%5d %02x %s%s" % (i, b, ch, mark))
