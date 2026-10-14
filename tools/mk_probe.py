# -*- coding: utf-8 -*-
"""生成 WAF 二分对照测试体到 state/ 目录。"""
import os

state = os.path.dirname(os.path.abspath(__file__))
mut = open(os.path.join(state, "..", "exp", "jboss", "bypass_mut.ser"), "rb").read()

open(os.path.join(state, "t1.bin"), "wb").write(b"A" * 400)
open(os.path.join(state, "t2.bin"), "wb").write(b"\xac\xed\x00\x05" + b"A" * 100)
open(os.path.join(state, "t3.bin"), "wb").write(mut[4:])
open(os.path.join(state, "t4.bin"), "wb").write(b"A" * 4 + mut[4:404])
print("probe bodies written")
