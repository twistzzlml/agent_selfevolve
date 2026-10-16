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


print("CapNew err=%d body=%s" % cmd(1, 17))
print("CanSuspend? (capabilities head):", end=" ")
err, b = cmd(1, 8)  # VM Suspend
print("VM Suspend err=%d" % err)
err, b = cmd(1, 4)  # AllThreads
(cnt,) = struct.unpack(">i", b[:4])
t1 = b[4:12]
print("AllThreads err=%d count=%d t1=%s" % (err, cnt, t1.hex()))
print("Name(t1) err=%d body=%s" % cmd(10, 1, t1))
err, b = cmd(1, 2, struct.pack(">I", 20) + b"Ljava/lang/Runtime;")
print("ClassesBySig Runtime err=%d body=%s" % (err, b.hex()[:40]))
# try ThreadGroup children again after suspend
err, b = cmd(1, 5)
gid = b[4:12]
print("TopGroups err=%d gid=%s" % (err, gid.hex()))
print("Children err=%d len=%d head=%s" % (lambda r: (r[0], len(r[1]), r[1][:40].hex()))(cmd(11, 3, gid)))
# resume VM
print("VM Resume err=%d" % cmd(1, 9)[0])
