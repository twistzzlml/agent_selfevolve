import socket
import struct

s = socket.create_connection(("172.23.0.2", 5005), timeout=15)
s.sendall(b"JDWP-Handshake")
print("hs:", s.recv(14))
pkt = struct.pack(">IIBBB", 11, 1, 0, 1, 7)
s.sendall(pkt)
hdr = b""
while len(hdr) < 11:
    hdr += s.recv(11 - len(hdr))
print("hdr:", hdr.hex())
ln, rid, flags, err = struct.unpack(">IIBH", hdr)
body = b""
while len(body) < ln - 11:
    body += s.recv(ln - 11 - len(body))
print("len", ln, "rid", rid, "flags", hex(flags), "err", err, "bodylen", len(body))
print("body:", body.hex())
