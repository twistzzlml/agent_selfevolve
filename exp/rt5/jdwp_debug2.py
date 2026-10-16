import socket
import struct

s = socket.create_connection(("172.23.0.2", 5005), timeout=15)
s.sendall(b"JDWP-Handshake")
s.recv(14)
ids = [0]


def cmd(cmdset, c, data=b""):
    ids[0] += 1
    pid = ids[0]
    s.sendall(struct.pack(">IIBBB", 11 + len(data), pid, 0, cmdset, c) + data)
    hdr = b""
    while len(hdr) < 11:
        hdr += s.recv(11 - len(hdr))
    ln, rid, flags, err = struct.unpack(">IIBH", hdr)
    body = b""
    while len(body) < ln - 11:
        body += s.recv(ln - 11 - len(body))
    return err, body


err, b = cmd(1, 7)
print("idSizes err=%d body=%s" % (err, b.hex()))
err, b = cmd(1, 4)
print("AllThreads err=%d" % err)
(cnt,) = struct.unpack(">i", b[:4])
print("count", cnt)
print("first ids:", [b[4 + i * 8: 12 + i * 8].hex() for i in range(min(cnt, 8))])
for t in [b[4:12], b[12:20], b[20:28]]:
    err, nb = cmd(10, 1, t)  # ThreadReference Name
    n = struct.unpack(">I", nb[:4])[0] if nb else -1
    print("Name(%s) err=%d -> %s" % (t.hex(), err, nb[4:4 + n].decode() if n > 0 else ""))
err, b = cmd(1, 5)  # TopLevelThreadGroups
print("TopGroups err=%d body=%s" % (err, b.hex()))
if err == 0:
    (g,) = struct.unpack(">i", b[:4])
    gid = b[4:12]
    err, cb = cmd(11, 3, gid)
    print("Children err=%d len=%d head=%s" % (err, len(cb), cb[:40].hex() if cb else ""))
