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


def rstr(b):
    n = struct.unpack(">I", b[:4])[0]
    return b[4:4 + n].decode("utf-8", "replace")


err, b = cmd(1, 1)  # Version
(nstr,) = struct.unpack(">i", b[0:4])
desc = b[4:4 + nstr].decode("utf-8", "replace")
off = 4 + nstr
(jdwp_maj, jdwp_min, vmver_n) = struct.unpack(">iiI", b[off:off + 12])
vmver = b[off + 12:off + 12 + vmver_n].decode()
off += 12 + vmver_n
(name_n,) = struct.unpack(">I", b[off:off + 4])
vmname = b[off + 4:off + 4 + name_n].decode()
print("Version err=%d desc=%r vmver=%r vmname=%r jdwp=%d.%d" % (err, desc, vmver, vmname, jdwp_maj, jdwp_min))

for sig in ["Ljava/lang/String;", "Ljava/lang/Object;", "Ljava/lang/Thread;",
            "Ljava/lang/Runtime;", "Ljava/lang/System;", "Lgroovy/lang/Script;"]:
    err, b = cmd(1, 2, struct.pack(">I", len(sig)) + sig.encode())
    (cnt,) = struct.unpack(">i", b[:4])
    print("ClassesBySignature %-28s err=%d count=%d" % (sig, err, cnt))

err, b = cmd(1, 3)  # AllClasses
(cnt,) = struct.unpack(">i", b[:4])
print("AllClasses err=%d count=%d" % (err, cnt))

err, b = cmd(1, 4)  # AllThreads after nothing
(cnt,) = struct.unpack(">i", b[:4])
t1 = b[4:12]
print("AllThreads err=%d count=%d" % (err, cnt))
print("ThreadStatus err=%d body=%s" % (cmd(10, 4, t1)[0], cmd(10, 4, t1)[1].hex()))
print("Suspend(t1) err=%d" % cmd(10, 2, t1)[0])
print("Name(t1) err=%d body=%s" % cmd(10, 1, t1))
