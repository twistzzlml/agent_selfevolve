# 公开 Exp 技术资料分类学调研：四个 CVE（JBoss / Shiro / OFBiz / GeoServer）

> **用途与合规声明**：本报告为【授权本地实验室评估】（本机 Docker 中的 vulhub 开源漏洞复现镜像）所做的纯文献综述，目的是支撑"靶场是否支持多样化测试用例"的评估结论。调研过程**未对任何系统发起网络请求、未发包、未执行任何攻击行为**，全部内容来自公开网页资料（NVD/GitHub/官方公告/技术博客）。本报告只做**公开技术资料的分类学梳理**（technique taxonomy），不提供可直接运行的攻击载荷代码；涉及载荷结构之处仅描述到"公开文档已公开的分类级别"，用于说明同一漏洞存在多种非等价测试构造。
>
> **调研方法**：NVD REST API（`services.nvd.nist.gov/rest/json/cves/2.0`）、GitHub raw/API（仓库 README、nuclei 模板、源码、commit）、官方 JIRA/公告页、技术博客抓取。个别来源抓取失败（见文末附录 A），已在对应位置标注。
>
> 调研日期：2026-10-13。

---

## 目录

1. [CVE-2017-12149 — JBoss AS HttpInvoker ReadOnlyAccessFilter 反序列化](#1-cve-2017-12149jboss-as-httpinvoker-readonlyaccessfilter-反序列化)
2. [CVE-2016-4437 — Apache Shiro rememberMe 默认密钥反序列化（Shiro-550）](#2-cve-2016-4437apache-shiro-rememberme-默认密钥反序列化shiro-550)
3. [CVE-2024-45507 — Apache OFBiz SSRF + Groovy 代码执行](#3-cve-2024-45507apache-ofbiz-ssrf--groovy-代码执行)
4. [CVE-2021-40822 — GeoServer TestWfsPost SSRF](#4-cve-2021-40822geoserver-testwfspost-ssrf)
5. [跨漏洞综合：对"靶场测试用例多样性"的启示](#5-跨漏洞综合对靶场测试用例多样性的启示)
6. [附录 A：抓取失败清单](#附录-a抓取失败清单)

---

## 1. CVE-2017-12149：JBoss AS HttpInvoker ReadOnlyAccessFilter 反序列化

### 1.1 漏洞成因与受影响版本

- **官方描述**（NVD，[CVE-2017-12149](https://nvd.nist.gov/vuln/detail/CVE-2017-12149)）：JBoss Application Server（随 Red Hat Enterprise Application Platform 5.2 交付）中，HTTP Invoker 的 `ReadOnlyAccessFilter` 的 `doFilter` 方法对反序列化的类**不做任何限制**，攻击者可通过构造的序列化数据执行任意代码。CWE-502（反序列化不可信数据）。NVD 参考链接：[Red Hat Bugzilla 1486220](https://bugzilla.redhat.com/show_bug.cgi?id=1486220)、[RHSA-2018:1607](https://access.redhat.com/errata/RHSA-2018:1607)、[RHSA-2018:1608](https://access.redhat.com/errata/RHSA-2018:1608)、[PoC 仓库（gottburgm/Exploits）](https://github.com/gottburgm/Exploits/tree/master/CVE-2017-12149)、[CISA KEV 目录](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)（已列入已知被利用漏洞）。
- **受影响版本**：
  - NVD CPE 仅列出 Red Hat JBoss EAP 5.0.0–5.2.2。注意：这是 CPE 配置不完整——公开 PoC 与 [vulhub 镜像](https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149)针对的是 **JBoss AS 6.1.0**（`/invoker/readonly` 在 AS 5.x/6.x 均存在）；Java-Deserialization-Cheat-Sheet 也标注该 CVE 适用于 "JBoss 6.X and EAP 5.X"（[来源](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)）。**此差异在公开资料中普遍存在，评测对照时建议以"http-invoker.sar 是否部署、readonly 入口是否存在"为判定标准而非版本号。**
  - [Bugzilla 1486220](https://bugzilla.redhat.com/show_bug.cgi?id=1486220)（官方一手记录）：受影响组件为 `http-invoker.sar/invoker.war`（存在于 `server/default/deploy` 与 `server/web/deploy` 等 profile 下）；**EAP 6/7 不再附带 http invoker，不受影响**；由 Joao F M Figueiredo 发现，2017-08-29 报告，2018-05 经 RHSA-2018:1607/1608 修复。
  - 官方缓解：为 http-invoker 的 `web.xml` 添加覆盖 `/*` 的 security-constraint，或整个移除 `http-invoker.sar`（Bugzilla 评论）。
- **漏洞成因（组件级）**：`ReadOnlyAccessFilter` 设计上想对请求做"只读"限制，但其 `doFilter` 在读取请求体时直接走 Java 原生 `ObjectInputStream` 反序列化，且未配置任何类过滤（无 serial filter / 白名单）。

### 1.2 公开资料与工具全景

| 类别 | 名称 | 说明 | 链接 |
|---|---|---|---|
| 官方记录 | Red Hat Bugzilla 1486220 | 一手漏洞报告与缓解方案 | https://bugzilla.redhat.com/show_bug.cgi?id=1486220 |
| 官方公告 | RHSA-2018:1607 / RHSA-2018:1608 | EAP 5 修复公告 | https://access.redhat.com/errata/RHSA-2018:1607 、 https://access.redhat.com/errata/RHSA-2018:1608 |
| 环境复现 | vulhub jboss/CVE-2017-12149 | JBoss AS 6.1.0 镜像 + `/invoker/readonly` + ysoserial CommonsCollections5 复现文档 | https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149 |
| 一手 PoC | gottburgm/Exploits（NVD 引用） | Perl 脚本，硬编码 CC 链（HashSet→TiedMapEntry→LazyMap→ChainedTransformer→InvokerTransformer→`getRuntime().invoke().exec()` 结构）打 `/invoker/readonly`，带 Basic 认证参数与本地验证 | https://github.com/gottburgm/Exploits/tree/master/CVE-2017-12149 |
| 集成工具 | JexBoss（joaomatosf/jexboss） | JBoss 3/4/5/6 多入口检测与利用（/admin-console、/jmx-console、/web-console/Invoker、/invoker/JMXInvokerServlet），并支持任意 HTTP 参数反序列化 | https://github.com/joaomatosf/jexboss |
| 载荷生成 | ysoserial（frohoff） | Java 反序列化 gadget 链标准生成器；各链依赖矩阵见 README | https://github.com/frohoff/ysoserial |
| 载荷生成扩展 | wh1t3p1g/ysoserial | 增加 CommonsCollections8/9/10、Spring3、RMIRefListener 等 | https://github.com/wh1t3p1g/ysoserial |
| 教学/演示 | joaomatosf/JavaDeserH2HC | H2HC 2017 演讲配套（含 JBoss readonly 示例），被 Cheat-Sheet 引用为 CVE-2017-12149 Details | https://github.com/joaomatosf/JavaDeserH2HC |
| 知识库 | Java-Deserialization-Cheat-Sheet（GrrrDog） | 按 CVE→入口路径→工具映射的 JBoss 条目全景 | https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet |
| 知识库 | FoxGlove Security 博客（2015） | Java 反序列化开山文（WebLogic/WebSphere/JBoss/Jenkins/OpenNMS） | https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ |
| 检测模板 | nuclei CVE-2017-12149 | 三入口连发（JMXInvokerServlet/EJBInvokerServlet/readonly）+ 无害 ArrayList 载荷，按响应特征判定 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12149.yaml |
| Burp 插件 | Freddy / Java Deserialization Scanner / Burp-ysoserial / JavaSerialKiller / SuperSerial | 反序列化通用检测（Cheat-Sheet 收录） | https://github.com/nccgroup/freddy 、 https://github.com/federicodotta/Java-Deserialization-Scanner 、 https://github.com/summitt/burp-ysoserial |
| 辅助工具 | Runtime-exec 命令转换器 | 解决 `Runtime.exec()` 不支持管道/重定向的编码转换（vulhub 文档引用） | http://www.jackson-t.ca/runtime-exec-payloads.html 、 https://ares-x.com/tools/runtime-exec/ |
| 二手转述 | vulhub 引用的微信公众号分析 | vulhub README 引用为漏洞分析参考（本次抓取被微信验证页拦截，未能核读，见附录 A） | https://mp.weixin.qq.com/s/zUJMt9hdGoz1TEOKy2Cgdg |

### 1.3 公开手法分类表

| # | 手法名称 | 原理一句话 | 适用条件 | 与其他手法的本质差异 | 出处 |
|---|---|---|---|---|---|
| 1 | `/invoker/readonly` 直接反序列化（本 CVE 核心入口） | POST 体是原生 Java 序列化流，`ReadOnlyAccessFilter.doFilter` 不过滤直接反序列化 | http-invoker.sar 已部署、readonly 未配置访问控制 | Filter 层入口，与 Servlet 层入口（#2/#3）代码路径不同 | https://nvd.nist.gov/vuln/detail/CVE-2017-12149 、 https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149 |
| 2 | `/invoker/JMXInvokerServlet` 反序列化 | JMX over HTTP 调用 Servlet 接受 `MarshalledInvocation` 序列化对象（对应更早的 CVE-2015-7501 时代入口） | jmx-invoker 服务部署（AS 4/5/6 常见） | Servlet 层通用 Invoker，非 readonly filter；nuclei 模板三入口之一 | https://github.com/joaomatosf/jexboss 、 https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12149.yaml |
| 3 | `/invoker/EJBInvokerServlet` 反序列化 | EJB 调用入口同样接受序列化对象 | 同上（EJB invoker 部署时） | 与 #2 同为 InvokerServlet 家族但部署组件不同 | 同上（nuclei 模板） |
| 4 | `/web-console/Invoker` 反序列化 | web-console 应用自带的 Invoker Servlet | web-console 未删除（旧默认部署） | 管理控制台应用内入口，非 http-invoker | https://github.com/joaomatosf/jexboss |
| 5 | `/jbossmq-httpil/HTTPServerILServlet`（CVE-2017-7504，AS 4.x） | JBossMQ 的 JMS over HTTP Invocation Layer 无限制反序列化 | JBoss AS ≤4.x 默认开启 | **不同 CVE、不同组件**（JMS 而非 http-invoker），常被并列复习，用于区分"同名入口不同根因" | https://nvd.nist.gov/vuln/detail/CVE-2017-7504 、 https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet |
| 6 | `/jmx-console` + `/admin-console` 部署类手法 | 通过 JMX 控制台（HtmlAdaptor）或 admin-console（JSF ViewState）部署/触发，非 readonly 本体 | 控制台未授权或已获凭据 | 部署/ViewState 类手法，jexboss 将其列为同机攻击面 | https://github.com/joaomatosf/jexboss |
| 7 | Gadget 家族选择：CC1/3/5/6/7 | 依赖 commons-collections 3.x 的 Transformer 链（vulhub 选 CC5 因镜像 Java 版本较新；CC6 系结构见 gottburgm 硬编码载荷） | 目机 classpath 有 CC 3.x | 与 #8 的本质差异是 **CC 3.x vs 4.0**（CC2/4 需 collections4） | https://github.com/frohoff/ysoserial 、 https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149 |
| 8 | Gadget 家族选择：CC2/4（collections4）、JBossInterceptors1/JavassistWeld1（javassist+jboss-interceptor/weld）、Spring1/2、Groovy1、Jdk7u21 | 按目标 classpath 可用库选择不同 gadget | 对应库存在于 JBoss 部署目录 | 依赖组合不同→同入口多种载荷可互换，构成载荷维度变异 | https://github.com/frohoff/ysoserial |
| 9 | URLDNS 检测链 | 只用 JDK 类触发一次 DNS 解析，无第三方依赖、不执行命令 | 仅需出网 DNS | 纯检测型，与 #7/#8 利用型相区分 | https://github.com/frohoff/ysoserial （payload 列表标注 "jre only vuln detect"） |
| 10 | JRMP 反连（JRMPClient + JRMPListener） | 载荷让目标反连攻击者 JRMPListener，绕过目标侧 payload 长度/依赖限制 | 目标可反连指定端口 | 利用通道变异：从"载荷内嵌执行"变为"外部反连" | https://github.com/insightglacier/Shiro_exploit README 同思路在 JBoss 场景通用（Cheat-Sheet RMI/JMX 章节） |
| 11 | 检测特征：`ClassCastException` 回显 / `ac ed 00 05` 魔数 / `application/x-java-serialized-object` Content-Type | 用无害序列化对象（如 ArrayList）探入口，按响应异常类与状态码（200/500）判定 | 无需出网 | 与 #9 的差异：不出网、基于响应特征 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12149.yaml 、 https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet （Detect 章节） |

### 1.4 可变异维度评估（公开资料证据）

1. **入口维度**：同一台 JBoss AS 6.1.0 上，公开资料使用了至少 3 个反序列化入口（readonly / JMXInvokerServlet / EJBInvokerServlet），外加 web-console/Invoker 与 admin-console——nuclei 模板把前三个放进同一条模板依次探测（[nuclei CVE-2017-12149](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-12149.yaml)），jexboss 则把 admin-console/jmx-console/web-console/Invoker 列为并行向量（[README](https://github.com/joaomatosf/jexboss)）。**这四个入口在部署组件、认证要求、过滤器行为上互不等价。**
2. **Gadget 维度**：vulhub 用 CC5、gottburgm 硬编码 CC6 系结构、ysoserial 提供从 CC1 到 Jdk7u21 的整族选择；链的选择取决于 CC 3.x/4.0 与其他库（javassist/weld/spring/groovy）是否在 classpath——同一漏洞至少 8+ 种非等价载荷（[ysoserial README](https://github.com/frohoff/ysoserial)）。
3. **验证通道维度**：不出网响应特征（ClassCastException + 状态码，nuclei）vs 出网 DNS（URLDNS）vs 反连 JRMP vs 命令执行结果落地验证（gottburgm 本地文件检查）——四种互斥的"证据获取方式"。
4. **编码/传输维度**：序列化体可直接 POST；`Runtime.exec` 不支持管道导致需要 `{echo,b64}|{base64,-d}|{bash,-i}` 式命令包装（[vulhub 文档](https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149)引用的转换器）；部分入口要求特定 Content-Type（gottburgm 用 `application/x-java-serialized-object`）。
5. **认证维度**：gottburgm 脚本带 `--username/--password` Basic 认证参数（部分部署对 invoker 加了认证），说明"有无凭据"也是公开工具已覆盖的分支条件。

**信息可信度**：官方公告/NVD/官方 Bugzilla（一手）；gottburgm、jexboss、nuclei、vulhub（一手 PoC/工具）；Cheat-Sheet 与 FoxGlove（二手汇编但指向一手）；微信公众号分析（二手转述，未能核读）。

---

## 2. CVE-2016-4437：Apache Shiro rememberMe 默认密钥反序列化（Shiro-550）

### 2.1 漏洞成因与受影响版本

- **官方描述**（NVD，[CVE-2016-4437](https://nvd.nist.gov/vuln/detail/CVE-2016-4437)）：Apache Shiro < 1.2.5，在"remember me"功能未配置 cipher key 时，攻击者可执行任意代码或绕过访问限制。NVD 参考含 [PacketStorm 137310（Information Disclosure, 2016-06）](http://packetstormsecurity.com/files/137310/Apache-Shiro-1.2.4-Information-Disclosure.html) 与 [PacketStorm 157497（RCE, 2020）](http://packetstormsecurity.com/files/157497/Apache-Shiro-1.2.4-Remote-Code-Execution.html)、[RHSA-2016-2035/2036](http://rhn.redhat.com/errata/RHSA-2016-2035.html)、[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)。
- **官方 Issue**（[SHIRO-550](https://issues.apache.org/jira/browse/SHIRO-550)，标题"Randomize default remember me cipher"，报告人 Tim Stibbs，2015-11-19 创建、修复于 1.2.5）：
  - `CookieRememberMeManager` 处理链：读取 rememberMe Cookie → Base64 解码 → **AES 解密** → Java 原生反序列化；
  - 默认 AES 密钥**硬编码在源码中**（`AbstractRememberMeManager` 的 `DEFAULT_CIPHER_KEY_BYTES`，即公开资料中通称的 `kPH+bIxk5D2deZiIxcaaaA==`）；
  - 即使应用从未启用 rememberMe 功能，只要用默认配置即受影响；报告确认已有针对 commons-collections 的可用利用（ysoserial CC4）。
  - 相关：SHIRO-441（RememberMe 原理与自定义密钥建议）。
- **后续演变（公开资料普遍记载）**：Shiro **1.4.2 起默认加密模式由 AES-CBC 改为 AES-GCM**，且不再内置固定密钥（未配置则随机生成）——旧工具的加密封装对新版失效，由此产生"CBC 版/GCM 版"两条公开利用分支（[Ares-X/shiro-exploit README](https://github.com/Ares-X/shiro-exploit)："新版本Shiro(>=1.4.2)采用了AES-GCM加密方式，导致旧版工具的加密算法无法正常利用漏洞…前提为新版Shiro在代码中指定了较常见的key或通过任意文件读取下载到了key"）。

### 2.2 公开资料与工具全景

| 类别 | 名称 | 说明 | 链接 |
|---|---|---|---|
| 官方记录 | SHIRO-550 JIRA | 默认密钥硬编码的一手 issue（含流程描述与修复版本） | https://issues.apache.org/jira/browse/SHIRO-550 |
| NVD | CVE-2016-4437 | 官方条目与参考 | https://nvd.nist.gov/vuln/detail/CVE-2016-4437 |
| 历史披露 | PacketStorm 137310 / 157497 | 2016 信息泄露（rememberMe 可伪造）与 2020 RCE 公告 | http://packetstormsecurity.com/files/137310/Apache-Shiro-1.2.4-Information-Disclosure.html 、 http://packetstormsecurity.com/files/157497/Apache-Shiro-1.2.4-Remote-Code-Execution.html |
| 中文首发分析 | Knownsec 博客《Apache Shiro RememberMe 1.2.4 反序列化》（2016-08） | 国内最早公开分析之一，被 Java-Deserialization-Cheat-Sheet 收录为 Shiro exploitation 参考（本次抓取失败，见附录 A） | http://blog.knownsec.com/2016/08/apache-shiro-java/ |
| 检测模板 | nuclei CVE-2016-4437 | 默认 key + AES-CBC + URLDNS(dns gadget) + Interactsh DNS 判定 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-4437.yaml |
| 检测/利用工具 | insightglacier/Shiro_exploit | **22 个网络收集 key** + ysoserial URLDNS + dnslog 检测；支持 Check/Exploit/Find-gadget 三模式与 JRMP 反连利用 | https://github.com/insightglacier/Shiro_exploit |
| 检测/利用工具 | feihong-cs/ShiroExploit-Deprecated（1956 星） | Shiro550+Shiro721 一键化；**SimplePrincipalCollection 原生对象筛选唯一 key**；ceye.io/dnslog.cn/JRMP+dnslog/回显 四种检测通道；多种 Tomcat 回显（配套 deserizationEcho） | https://github.com/feihong-cs/ShiroExploit-Deprecated 、 https://github.com/feihong-cs/deserizationEcho |
| 检测/利用工具 | Ares-X/shiro-exploit | 支持 AES-GCM（v2）与 AES-CBC（v1）；check 模式**无需 dnslog**；内置 xray 6 条 Tomcat 回显链（CommonsCollectionsK1/K2、CommonsBeanutils1/2、Jdk7u21、Jdk8u20） | https://github.com/Ares-X/shiro-exploit |
| 利用工具 | wuppp/shiro_rce_exp | Shiro-721 Padding Oracle RCE 脚本 | https://github.com/wuppp/shiro_rce_exp |
| Burp 被动插件 | pmiaowu/BurpShiroPassiveScan（~1.8k 星） | 框架指纹 + key 检测（CBC/GCM）；采用 l1nk3r 基于原生 Shiro 的检测法（无需 dnslog、不出网不漏报、密文更短） | https://github.com/pmiaowu/BurpShiroPassiveScan |
| Burp 被动插件 | Daybr4ak/ShiroScan | 无 dnslog key 检测（依据微信文章，工具已并入上者） | https://github.com/Daybr4ak/ShiroScan |
| Key 收集库 | yanm1e/shiro_key | **1000+ key** 收集列表（含默认 key、大量变体、可读 base64 串如 `bWljcm9z`(micros)、`Z3Vucw==`(guns)、`cmVtZW1iZXJNZQ==`(rememberMe) 等） | https://github.com/yanm1e/shiro_key |
| Key 收集库 | 0xShe/Shiro-key-10w | "十万量级" key 列表 | https://github.com/0xShe/Shiro-key-10w |
| 其他工具 | Ggasdfg321/shiro_check、myzxcg/ShiroKeyCheck（Go）、bkfish/Awesome_shiro、SummerSec/AgentInjectTool（读取/修改目标 key） | 批量/Go 实现/后利用 | https://github.com/Ggasdfg321/shiro_check 、 https://github.com/myzxcg/ShiroKeyCheck 、 https://github.com/bkfish/Awesome_shiro 、 https://github.com/SummerSec/AgentInjectTool |
| 无依赖链理论 | P神（leavesongs）《CommonsBeanutils与无commons-collections的Shiro反序列化》（2021-04） | CB 链在 Shiro 环境失败的根因与构造方案 | https://www.leavesongs.com/penetration/commons-beanutils-without-commons-collections.html |
| 无依赖链实践 | cnblogs bitterz《从commons-beanutils反序列化到shiro无依赖的漏洞利用》（含内存马）；yyhuni《ysoserial-CommonsBeanutils1的shiro无依赖链改造》；wh1sper《Shiro反序列化的终点：cbu 和 no CC 利用链》 | 改造 CB1 / 回显 / 内存马 | https://www.cnblogs.com/bitterz/p/15401105.html 、 https://www.cnblogs.com/yyhuni/p/15644299.html 、 https://blog.wh1sper.com/posts/shiro%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E7%9A%84%E7%BB%88%E7%82%B9cbu%E5%92%8Cno-cc%E5%88%A9%E7%94%A8%E9%93%BE |
| Shiro-721 | anquanke《Shiro RememberMe 反序列化漏洞（Padding Oracle Attack）》（00theway，2019-11） | CVE-2019-12422 原理（CBC padding oracle 反向加密），需有效 rememberMe cookie，以 deleteMe 为 oracle | https://www.anquanke.com/post/id/192819 |
| 知识库 | Java-Deserialization-Cheat-Sheet（Apache Shiro 条目） | 收录 SHIRO-550 与已知中文分析 | https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet |

> 注：广为流传的集成工具 "AabyssZG/ShiroAttack2" 目前仓库返回 404（本次以 GitHub API 验证），其 README 无法核读，标注**待验证**；其功能定位与 Ares-X/shiro-exploit、SummerSec/ShiroAttack2 一脉相承（key 爆破 + GCM + 回显）。

### 2.3 公开手法分类表

| # | 手法名称 | 原理一句话 | 适用条件 | 与其他手法的本质差异 | 出处 |
|---|---|---|---|---|---|
| 1 | 默认 key 直打（经典 Shiro-550） | 用源码硬编码 key 加密"序列化 gadget"，服务端 AES-CBC 解密后反序列化 | Shiro <1.2.5 或开发者复制了默认 key | 单 key、无爆破，是一切变体的基线 | https://issues.apache.org/jira/browse/SHIRO-550 、 https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-4437.yaml |
| 2 | Key 列表爆破（22→100+→1k+→10 万级） | 对收集 key 逐个加密探测载荷 | 目标使用了"常见自定义 key"（教程/开源项目/SDK 示例中泄漏的 key） | 与 #1 的差异是**key 空间扩展**；key 越来越多的原因：官方改随机 key 后，公开工具把"曾在开源代码/教程/配置中出现过的 key"逐步收编进列表（yanm1e 列表中大量"变体/错拼/可读串"即为实证） | https://github.com/insightglacier/Shiro_exploit 、 https://github.com/yanm1e/shiro_key 、 https://github.com/0xShe/Shiro-key-10w |
| 3 | deleteMe 响应判定（无 dnslog key 检测） | key 错误→解密失败→响应 `Set-Cookie: rememberMe=deleteMe`；key 正确（配合法序列化对象）→无 deleteMe，以此区分 key | 任何可发 cookie 的目标，**不出网也可用** | 与 #5 的差异：纯响应侧 oracle，不依赖外带通道；也是 Shiro 框架指纹本身 | https://github.com/Daybr4ak/ShiroScan 、 https://github.com/pmiaowu/BurpShiroPassiveScan |
| 4 | SimplePrincipalCollection 原生对象探测 | 用 Shiro 自带、全环境可反序列化的 `SimplePrincipalCollection` 作为无害载荷筛选 key，一次请求即可确认 key 正确且不触发任何执行 | 同上；比 URLDNS 更快、请求更少、密文更短 | 与 #3 结合构成"原生类探测"流派；与 URLDNS 流派的本质差异：**不依赖出网** | https://github.com/feihong-cs/ShiroExploit-Deprecated 、 https://github.com/pmiaowu/BurpShiroPassiveScan （l1nk3r 方法） |
| 5 | URLDNS 外带检测 | 反序列化链仅触发 `URL` 对象 DNS 解析，靠 dnslog/ceye/Interactsh 回连确认"反序列化发生+key 正确" | 目标能出网 DNS | 检测型链（无第三方依赖、无命令执行），与 #6 利用型链相区分 | https://github.com/frohoff/ysoserial 、 https://github.com/insightglacier/Shiro_exploit 、 https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-4437.yaml |
| 6a | 有依赖利用链（CC 系） | CommonsCollections1/3/5/6/7（CC 3.x）或 CC2/4（collections4）执行命令/反连 | 目标 classpath 含对应 commons-collections 版本 | 依赖 commons-collections；Shiro 发行包**通常不带** CC，故常失败 | https://github.com/frohoff/ysoserial |
| 6b | 无依赖利用链（CommonsBeanutils 改造，"no CC"） | Shiro 必带 commons-beanutils（其内部 shaded 了一部分 CC）；用 `BeanComparator`+`TemplatesImpl`，把 ysoserial CB1 默认的 `ComparableComparator`（属 CC，目标缺失会 `NoClassDefFoundError`）替换为 JDK 自带 `String.CASE_INSENSITIVE_ORDER`（CaseInsensitiveComparator），并把 CB `serialVersionUID` 对齐 Shiro 捆绑的 1.8.3 | Shiro 默认依赖环境即可 | 与 6a 的本质差异：**依赖面收窄到 Shiro 自带 jar**；工程点是 Comparator 替换 + serialVersionUID 版本对齐 | https://www.leavesongs.com/penetration/commons-beanutils-without-commons-collections.html 、 https://www.cnblogs.com/yyhuni/p/15644299.html |
| 7 | 回显链 / 内存马 | Tomcat 回显（xray K1/K2、CB1/CB2、Jdk7u21/8u20 等 6 条）或向 Tomcat StandardContext 注入 listener/Filter 内存马（如冰蝎型） | 目标 Tomcat 环境、依赖匹配 | 输出通道变异：从"命令执行"到"结果回显"到"驻留内存马" | https://github.com/Ares-X/shiro-exploit 、 https://www.cnblogs.com/bitterz/p/15401105.html |
| 8 | JRMP 反连（JRMPClient→外部 JRMPListener） | cookie 只装一个反连 gadget，真正的利用载荷在外部 JRMP 服务上按需切换 | 目标可反连 | 显著减小 cookie 体积（feihong README 明言），绕过长 cookie/WAF 限制 | https://github.com/feihong-cs/ShiroExploit-Deprecated |
| 9 | Shiro-721 Padding Oracle（CVE-2019-12422，关联漏洞） | 不需要 key：利用 AES-CBC 解密的 padding oracle，用**有效 rememberMe cookie 作 oracle**逐块反向构造出含恶意序列化数据的合法密文（利用"序列化流后附脏数据不影响反序列化"特性）；以 deleteMe 为判定 | 任意版本 CBC 模式 + 一个有效登录 rememberMe cookie；1.4.2 改 GCM 后不可用 | 与 550 的本质差异：**无需密钥**但需要合法 cookie（前置条件互换）；wuppp 工具与 feihong 工具均实现 721 | https://www.anquanke.com/post/id/192819 、 https://github.com/wuppp/shiro_rce_exp 、 https://github.com/feihong-cs/ShiroExploit-Deprecated |
| 10 | CBC→GCM 版本分叉处理 | ≥1.4.2 用 AES-GCM 封装（v2），旧 CBC 封装（v1）失效；工具双模式自动尝试 | 新版 Shiro 但 key 泄漏（代码中写死/任意文件读取获得） | 加密模式维度的非等价分支，工具需同时支持两种封装 | https://github.com/Ares-X/shiro-exploit 、 https://github.com/pmiaowu/BurpShiroPassiveScan |

### 2.4 可变异维度评估（公开资料证据）

1. **Key 维度**：默认 key → 常见泄漏 key 集合（22 个，[insightglacier](https://github.com/insightglacier/Shiro_exploit)）→ 1000+（[yanm1e/shiro_key](https://github.com/yanm1e/shiro_key)）→ 十万级（[0xShe/Shiro-key-10w](https://github.com/0xShe/Shiro-key-10w)）。key 列表"越来越多"的公开解释即：官方 1.2.5 随机化后（[SHIRO-550](https://issues.apache.org/jira/browse/SHIRO-550)），大量应用在代码里写死了自定义 key，这些 key 随开源项目、教程、配置模板、镜像被逐步收集；yanm1e 列表中可见大量"近亲变体"与可读 base64 串，证明其中相当一部分来自对公开样本的枚举式收编。
2. **加密模式维度**：AES-CBC（<1.4.2）vs AES-GCM（≥1.4.2）——两种互不兼容的封装，工具侧普遍以 `-v 1/2` 或自动双试实现（[Ares-X](https://github.com/Ares-X/shiro-exploit)、[BurpShiroPassiveScan](https://github.com/pmiaowu/BurpShiroPassiveScan)）。
3. **检测通道维度**：DNS 外带（dnslog/ceye/Interactsh，[nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2016/CVE-2016-4437.yaml)、[insightglacier](https://github.com/insightglacier/Shiro_exploit)）vs 响应侧 deleteMe oracle（[ShiroScan](https://github.com/Daybr4ak/ShiroScan)）vs 原生类探测（SimplePrincipalCollection，[feihong](https://github.com/feihong-cs/ShiroExploit-Deprecated)、l1nk3r 法）——后两者对**不出网目标**是唯一可行解，这是三种检测手法的本质差异点。
4. **利用链维度**：CC 有依赖 vs CB 无依赖（[leavesongs](https://www.leavesongs.com/penetration/commons-beanutils-without-commons-collections.html)）vs JRMP 外挂（[feihong](https://github.com/feihong-cs/ShiroExploit-Deprecated)）vs Jdk7u21/8u20 纯 JDK——四种依赖面互斥的执行路径。
5. **输出/后利用维度**：无回显命令 → Tomcat 回显（xray 6 链）→ 内存马驻留（[bitterz](https://www.cnblogs.com/bitterz/p/15401105.html)）。
6. **前置条件维度**：Shiro-721 展示了"无 key 但需合法 cookie"的镜像条件组合（[anquanke 192819](https://www.anquanke.com/post/id/192819)），与 550 的"有 key 无需 cookie"构成公开资料中明确对照的两分支。

**信息可信度**：SHIRO-550 JIRA / NVD / PacketStorm（官方一手）；nuclei 模板、各工具 README、leavesongs/anquanke 技术文章（一手 PoC/分析）；微信文章转述的检测思路（二手，经 ShiroScan README 引用）；knownsec 2016 原文（未能直接核读，标注）。

---

## 3. CVE-2024-45507：Apache OFBiz SSRF + Groovy 代码执行

### 3.1 漏洞成因与受影响版本

- **官方描述**（NVD，[CVE-2024-45507](https://nvd.nist.gov/vuln/detail/CVE-2024-45507)）：Apache OFBiz 的 SSRF 与代码生成控制不当（Code Injection），影响 **18.12.16 之前**所有版本，建议升级至 18.12.16。CWE-918（SSRF）+ CWE-94（代码注入）。官方参考：[OFBIZ-13132](https://issues.apache.org/jira/browse/OFBIZ-13132)、[Apache 邮件列表公告](https://lists.apache.org/thread/o90dd9lbk1hh3t2557t2y2qvrh92p7wy)、[oss-security 邮件](http://www.openwall.com/lists/oss-security/2024/09/03/7)、[OFBiz 安全页](https://ofbiz.apache.org/security.html)。
- **漏洞成因链**（据公开分析）：
  1. `webtools` 的 Stats 统计页面中，[StatsScreens.xml](https://github.com/apache/ofbiz-framework/blob/release18.12/applications/webtools/widget/StatsScreens.xml) 的装饰器声明直接引用用户参数：`<decorator-screen name="StatsDecorator" location="${parameters.statsDecoratorLocation}">`（[dottak.me 分析](https://www.dottak.me/posts/2025-03-04-apache-ofbiz-1-day-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0-6-cve-2024-45507)）；
  2. 渲染时 `ScreenFactory.getScreensFromLocation(resourceName)` → `FlexibleLocation.resolveLocation()` **支持把任意字符串（含 `http(s)://` 外部 URL）解析为 XML 来源**并 `UtilXml.readXmlDocument` 加载——SSRF 阶段（[修复 commit diff](https://github.com/apache/ofbiz-framework/commit/ffb1bc487983fa672ac4fbeccf7ed7175e2accd3) 中被拦截的正是这行）；
  3. 加载进来的攻击者 XML 是合法的 OFBiz Widget-Screen 格式，`<actions><set value="${groovy:'...'.execute();}"/></actions>` 中的 Groovy 表达式会被 `GroovyUtil` 求值——RCE 阶段；
  4. 同一修复还覆盖了 Groovy/脚本路径加载（`GroovyUtil.getScriptClassFromLocation`、`ScriptUtil.compileScriptFile/executeScript`），即"Screen XML 路径"与"脚本路径"两个被污染入口都在补丁范围内（commit diff 实证）。
- **修复**：[commit ffb1bc4879](https://github.com/apache/ofbiz-framework/commit/ffb1bc487983fa672ac4fbeccf7ed7175e2accd3)（"Improved: Added validation to screen/script URI to block URL patterns. Throw an error if the script location contains a URL. (OFBIZ-13132)"，Deepak Dixit，2024-08-29）：在 `ScreenFactory/GroovyUtil/ScriptUtil` 三处增加 `UtilValidate.urlInString(...)` 校验，脚本/Screen 位置含 URL 即抛异常。[OFBIZ-13132](https://issues.apache.org/jira/browse/OFBIZ-13132) 标题即"Add validation to screen/script URI to block URL patterns"，影响版本 18.12.15、修复版本 18.12.16。dottak.me 另引用同 issue 下的 commit `28f5f87ec9`（新增 `UtilValidate.urlInString` 方法、仅允许 `component://` 内部资源引用）——两 commit 同属本修复集，关系**待验证**（未逐条核对 commit 谱系）。

### 3.2 公开资料与工具全景

| 类别 | 名称 | 说明 | 链接 |
|---|---|---|---|
| 官方 | OFBIZ-13132 / 邮件公告 / oss-security / 修复 commit | 一手来源 | https://issues.apache.org/jira/browse/OFBIZ-13132 、 https://lists.apache.org/thread/o90dd9lbk1hh3t2557t2y2qvrh92p7wy 、 http://www.openwall.com/lists/oss-security/2024/09/03/7 、 https://github.com/apache/ofbiz-framework/commit/ffb1bc487983fa672ac4fbeccf7ed7175e2accd3 |
| 分析（用户指定） | seebug Paper 3228 | 知道创宇 404 实验室分析（站点 521/存档 429 未能抓取正文，仅可经 vulhub/Threekiii 转引，见附录 A） | https://paper.seebug.org/3228/ |
| 分析（用户指定） | 先知社区 t/15569 | 先知分析（重定向到 /news/15006 后被反爬 JS 拦截，未能抓取正文，见附录 A） | https://xz.aliyun.com/t/15569 （重定向：https://xz.aliyun.com/news/15006 ） |
| 分析 | 腾讯云开发者社区《CVE-2024-45507 分析学习（Poc，EXP）》（2024-11） | 含三要素成因、未授权可达路径、Unicode 转义 payload、批量验证正则与测绘语法 | https://cloud.tencent.com/developer/article/2468445 |
| 分析 | dottak.me（韩文）OFBiz 1-day 系列第 6 篇 | 给出 StatsScreens.xml 源码级成因、与 CVE-2024-45195 的端点级对比、修复 commit | https://www.dottak.me/posts/2025-03-04-apache-ofbiz-1-day-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0-6-cve-2024-45507 |
| 环境复现 | vulhub ofbiz/CVE-2024-45507 | OFBiz 18.12.15 镜像；SSRF 与 RCE 两段复现文档 | https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45507 |
| 检测模板 | nuclei CVE-2024-45507 | 入口用 `/webtools/control/view/StatsSinceStart`；XML 经 base64+双重 URL 编码塞进远程 URL 的 `b64_body` 参数由回连服务返回；Interactsh 判定 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45507.yaml |
| 一手 PoC | Avento/CVE-2024-45507_Behinder_Webshell | `testofbiz.groovy`：Groovy 载荷内反射遍历 Tomcat `StandardContext` 注入 listener 型内存马（gzip+base64 类字节）， demonstrates "Groovy→内存马"后利用形态 | https://github.com/Avento/CVE-2024-45507_Behinder_Webshell |
| 汇编 | Threekiii/Vulnerability-Wiki（OFBiz CVE-2024-45507 条目） | 与 vulhub 同源复现文档 + 双包 wget/bash 反弹法 | https://github.com/Threekiii/Vulnerability-Wiki/blob/master/docs-base/docs/framework/Apache-OFBiz-SSRF-%E5%92%8C%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E-CVE-2024-45507.md |
| 关联漏洞 | CVE-2024-45195（Forced Browsing）、CVE-2024-32113、CVE-2024-36104、CVE-2023-51467/49070 | 同期 OFBiz 系列，公开仓库常并排收录 | https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass 、 https://github.com/Mr-xn/CVE-2024-32113 、 https://github.com/Groppoxx/CVE-2024-36104-PoC |

### 3.3 公开手法分类表

| # | 手法名称 | 原理一句话 | 适用条件 | 与其他手法的本质差异 | 出处 |
|---|---|---|---|---|---|
| 1 | `POST /webtools/control/forgotPassword/StatsSinceStart` + `statsDecoratorLocation`（vulhub 主线入口） | 参数被当作 Screen XML 装饰器位置解析，`FlexibleLocation` 支持远程 URL | <18.12.16；该 view 未做视图授权拦截 | "forgotPassword" 前缀路由与 "view" 路由映射到同一 view，但控制器配置不同 | https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45507 、 https://github.com/Threekiii/Vulnerability-Wiki/blob/master/docs-base/docs/framework/Apache-OFBiz-SSRF-%E5%92%8C%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E-CVE-2024-45507.md |
| 2 | `POST /webtools/control/view/StatsSinceStart`（nuclei 入口） | 同一 view 的另一控制器路径，无需 forgotPassword 前缀 | 同上 | 入口等价但配置路径不同；nuclei 与 vulhub 各用其一即为实证 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45507.yaml |
| 3 | `findTemporalExpression` 入口 + `tempExprDecoratorLocation`（姊妹向量） | 登录路由返回 error 分支可达 TempExprScreens.xml，其 `tempExprDecoratorLocation` 与 statsDecoratorLocation 同型，引入外部 XML | 未授权可达（腾讯云实测两个路径：`/webtools/control/main/findTemporalExpression`、`/webtools/control/forgotPassword/findTemporalExpression`） | **不同参数名 + 不同 Screen 文件**，但根因同为 Screen 位置未校验——同一漏洞的"第二个参数面" | https://cloud.tencent.com/developer/article/2468445 |
| 4 | 纯 SSRF 探测 | `statsDecoratorLocation=http://attacker/` 使服务端发起到攻击者服务的请求，观察回连 | 需要攻击者可控 HTTP 服务（或 OAST） | 只验证"远程位置被解析加载"，不触发 Groovy | https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45507 、 https://cloud.tencent.com/developer/article/2468445 |
| 5 | SSRF→RCE（远程托管恶意 Widget-Screen XML） | 攻击者服务返回合法 `<screens>` XML，`<set value="${groovy:'cmd'.execute();}"/>` 被 GroovyUtil 求值 | 目标需能访问攻击者 XML 托管地址（出网） | 与 #4 的本质差异：SSRF 之外增加了"远程 XML→表达式求值"第二跳 | https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45507 、 https://www.dottak.me/posts/2025-03-04-apache-ofbiz-1-day-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0-6-cve-2024-45507 |
| 6 | `b64_body` 自托管技巧 | 把整份 XML base64+双重 URL 编码塞进指向 OAST/回连平台的 URL 参数，由该平台把解码内容作为响应体返回 | 使用的回连平台支持把 query 参数回显为响应体 | 免自建 HTTP 托管，适合扫描器一键化（nuclei 模板实现） | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45507.yaml |
| 7 | Groovy 载荷形态分叉：`'cmd'.execute()` vs `Runtime.exec()` vs `.execute().text` 探测 | 字符串 `.execute()` 不经 shell（无管道）；需要管道/重定向时改 `Runtime.getRuntime().exec()` 或两段式（先 wget 再 bash）；`.text` 可探测有无回显位 | 视命令复杂度与验证通道选择 | 载荷编码维度：vulhub 用两段 wget+bash；腾讯云用 `{echo,b64}|{base64,-d}|{bash,-i}`+Unicode 转义；dottak 用 `.execute().text` 判回显 | https://github.com/Threekiii/Vulnerability-Wiki/blob/master/docs-base/docs/framework/Apache-OFBiz-SSRF-%E5%92%8C%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E-CVE-2024-45507.md 、 https://cloud.tencent.com/developer/article/2468445 、 https://www.dottak.me/posts/2025-03-04-apache-ofbiz-1-day-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0-6-cve-2024-45507 |
| 8 | 验证/判定通道：反弹 shell vs 响应标记 vs OAST | 页面无命令回显位→公开资料分别用反弹 shell、响应中 `<!-- Begin Screen ...#StatsDecorator -->` 注释正则、Interactsh DNS/HTTP 回连确认 | 各自依赖：可反连 / 无需出网 / 需 OAST | 三种互斥证据获取方式 | https://www.dottak.me/posts/2025-03-04-apache-ofbiz-1-day-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0-6-cve-2024-45507 、 https://cloud.tencent.com/developer/article/2468445 、 https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45507.yaml |
| 9 | Groovy→内存马后利用 | Groovy 载荷内反射获取 Tomcat `StandardContext`，注册恶意 listener（类字节 gzip+base64 内嵌），实现驻留 | 已获 RCE，Tomcat 容器 | 从一次性执行到持久化，属后利用阶段变异 | https://github.com/Avento/CVE-2024-45507_Behinder_Webshell |
| 10 | 与 CVE-2024-45195 的端点区分 | 45195 是 ViewDataFile 强制浏览（未认证直读受限资源），45507 是 Screen 位置注入——公开分析常并排对比防混淆 | — | 同一框架、不同根因，靶场设计时应作为独立用例 | https://www.dottak.me/posts/2025-03-04-apache-ofbiz-1-day-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0-6-cve-2024-45507 |

### 3.4 可变异维度评估（公开资料证据）

1. **入口维度**：`forgotPassword/StatsSinceStart`（vulhub/Threekiii）、`view/StatsSinceStart`（[nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45507.yaml)）、`main/findTemporalExpression` 与 `forgotPassword/findTemporalExpression` + `tempExprDecoratorLocation`（[腾讯云](https://cloud.tencent.com/developer/article/2468445)）——至少 4 个公开入口/参数组合，且修复 commit 将 ScreenFactory/GroovyUtil/ScriptUtil 三处一并封堵，说明公开资料发现的入口并不完备、各入口互不等价。
2. **鉴权前提维度（公开资料存在分歧）**：vulhub/腾讯云称可未授权利用（vulhub 示例无 cookie；腾讯云实测 forgotPassword 路径未授权可达）；dottak.me 称需要有效 JSESSIONID；nuclei 模板不带 cookie 即判定。标注**待验证**——可能与 OFBiz 视图授权配置、具体入口路径有关，靶场评测时两种前提都应作为用例。
3. **托管方式维度**：自建 HTTP 服务（vulhub/Threekiii/dottak）vs 回连平台 `b64_body` 回显（nuclei）——决定测试是否需要"出网到攻击者服务器"。
4. **载荷编码维度**：明文 Groovy / `{echo,b64}|{base64,-d}|{bash,-i}` 包装 + Unicode 转义（腾讯云）/ 双包 wget+bash（Threekiii）/ `.execute().text` 回显探测（dottak）——四种非等价命令执行构造。
5. **证据通道维度**：反弹 shell、响应内 Screen 注释正则、OAST 回连、`touch /tmp/success` 落地检查（vulhub）——四种判定方式。
6. **后利用维度**：内存马注入（[Avento](https://github.com/Avento/CVE-2024-45507_Behinder_Webshell)）超越单次验证，属于公开 PoC 中已出现的扩展形态。

**信息可信度**：OFBIZ-13132/邮件列表/修复 commit（官方一手）；vulhub、nuclei、Avento、dottak、腾讯云（一手 PoC/分析）；seebug 3228 与先知 15569（用户指定的两个来源，本次均未能抓取正文，其结论仅以 Threekiii/vulhub 的转引形式间接进入本报告，见附录 A）。

---

## 4. CVE-2021-40822：GeoServer TestWfsPost SSRF

### 4.1 漏洞成因与受影响版本

- **官方描述**（NVD，[CVE-2021-40822](https://nvd.nist.gov/vuln/detail/CVE-2021-40822)）：GeoServer ≤2.18.5 及 2.19.0–2.19.2 允许"通过设置代理主机的选项"进行 SSRF。CWE-918。
- **公告编号勘误（重要）**：用户提示中的 **GHSA-7g5f-wrx8-5ccf 并非本 CVE**——该编号对应 [CVE-2023-25157](https://github.com/advisories/GHSA-7g5f-wrx8-5ccf)（GeoServer OGC Filter SQL 注入，`gs-jdbcconfig`）。CVE-2021-40822 的正确公告为：
  - GitHub 数据库条目：[GHSA-rr33-j5p5-ppf8](https://github.com/advisories/GHSA-rr33-j5p5-ppf8)（High 7.5，`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`，受影响 ≤2.18.5 与 2.19.0–2.19.2，未标注修复版本）；
  - GeoServer 官方仓库公告：[GHSA-68cf-j696-wvv9](https://github.com/geoserver/geoserver/security/advisories/GHSA-68cf-j696-wvv9)（2025-06-10 发布，`Missing checks allow for SSRF to specific targets using the TestWfsPost endpoint`，受影响 >=1.0.0，**修复于 2.24.4 / 2.25.2**）；
  - 同端点的姊妹公告：[GHSA-5gw5-jccf-6hxw / CVE-2024-29198](https://github.com/geoserver/geoserver/security/advisories/GHSA-5gw5-jccf-6hxw)（"Unauthenticated SSRF via TestWfsPost"，受影响 >=2.0.0 <2.24.4 及 2.25.0/2.25.1，修复 2.24.4/2.25.2）。
  - 重复编号的官方解释：[GeoServer 2025-06-10 披露页](https://geoserver.org/vulnerability/2025/06/10/cve-disclosure.html)——"CVE-2021-40822 being generated prior to our use of CVE records"，即项目早期未使用 CVE 记录制度导致重复编号。**注意：vulhub 的 geoserver/CVE-2021-40822 README 也误引了 GHSA-7g5f-wrx8-5ccf**（[vulhub README](https://github.com/vulhub/vulhub/blob/master/geoserver/CVE-2021-40822/README.md)），该误引即用户提示中错误的来源。
- **官方工单**（[GEOS-10229](https://osgeo-org.atlassian.net/browse/GEOS-10229)）：2021-09-10 由报告者 "phor3nsic bugs"（gccybermonks/phor3nsic_br）提交；其评论明确利用条件——"GEOSERVER 未正确校验发起请求所用的 host……**当 global.xml 中 proxyBaseUrl 为 null 时**可配置代理并形成完整 SSRF，导致内网访问"；由于团队长期未响应，2022-02 由 Mitre 直接分配 CVE；直到 2.24.4/2.25.2（2024/2025）才修复。
- **组件级成因**（源码一手，[TestWfsPost.java @2.19.1](https://github.com/geoserver/geoserver/blob/2.19.1/src/wfs/src/main/java/org/vfny/geoserver/wfs/servlets/TestWfsPost.java)）：
  - `TestWfsPost` 是 WFS 演示（Demo Request）Servlet：无参数访问时输出一个 HTML 测试表单；带参数时服务端向 `url` 参数指定的地址转发请求；
  - 参数：`url`（转发目标）、`body`（为空则 GET，非空则以 `application/xml` POST）、`username`/`password`（拼成 Basic 认证头）；
  - 实现 `new URL(urlString).openConnection()` 后**强转为 `java.net.HttpURLConnection`**——这决定了 `file://`、`ftp://`、`data://` 等非 http(s) 协议在运行期强转失败；
  - `validateURL()` 校验目标 host 必须等于 Proxy Base URL 的 host（若已配置）或**当前请求自身的 host**（`request.getRequestURL()`，可被 Host 请求头影响）——host 字符串相等性校验即被绕过的点。

### 4.2 公开资料与工具全景

| 类别 | 名称 | 说明 | 链接 |
|---|---|---|---|
| 官方公告 | GHSA-rr33-j5p5-ppf8 / GHSA-68cf-j696-wvv9 / GHSA-5gw5-jccf-6hxw / GEOS-10229 / 官方披露页 | 见 4.1 | https://github.com/advisories/GHSA-rr33-j5p5-ppf8 、 https://github.com/geoserver/geoserver/security/advisories/GHSA-68cf-j696-wvv9 、 https://github.com/geoserver/geoserver/security/advisories/GHSA-5gw5-jccf-6hxw 、 https://osgeo-org.atlassian.net/browse/GEOS-10229 、 https://geoserver.org/vulnerability/2025/06/10/cve-disclosure.html |
| 源码 | TestWfsPost.java（2.19.1 tag） | 一手实现：参数语义、HttpURLConnection 强转、validateURL host 校验 | https://github.com/geoserver/geoserver/blob/2.19.1/src/wfs/src/main/java/org/vfny/geoserver/wfs/servlets/TestWfsPost.java |
| 原始分析 | GCCyberMonks《SSRF Geoserver (CVE-2021-40822)》（2022-05-17，报告者本人） | 完整时间线（2021-09-03 报告→09-10 建 JIRA→2022-02-18 获 CVE）；明确记载 file://、ftp://、data:// 协议尝试均被同一错误拒绝；Host 头伪造绕过校验；`/geoserver` 上下文路径与 `/../` 回根技巧；非盲 SSRF（响应体回显）；缓解：在 globals.xml 设置 proxyBaseUrl | https://gccybermonks.com/posts/cve-2021-40822/ |
| 一手 PoC | phor3nsic/CVE-2021-40822 | 报告者的 PoC 脚本（`Host: example.com` 头 + `url=http://pudim.com.br`）与 docker 化靶场 | https://github.com/phor3nsic/CVE-2021-40822 |
| 检测模板 | nuclei CVE-2021-40822 | 两步 flow（先探测 GeoServer 页面）；`Host: oast.pro` + `url=http://oast.pro/geoserver/../` + `body=&username=&password=`；Interactsh 判定 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40822.yaml |
| 环境复现 | vulhub geoserver/CVE-2021-40822 | 2.19.1 镜像；明确记载"url 参数中的 host 必须与请求 Host 头一致，否则报错" | https://github.com/vulhub/vulhub/blob/master/geoserver/CVE-2021-40822/README.md |
| 漏洞库 | Acunetix 条目 | "允许未认证攻击者向内网发送任意请求" | https://www.acunetix.com/vulnerabilities/web/geoserver-ssrf-cve-2021-40822 |

### 4.3 公开手法分类表

| # | 手法名称 | 原理一句话 | 适用条件 | 与其他手法的本质差异 | 出处 |
|---|---|---|---|---|---|
| 1 | Host 头伪造绕过 host 校验 | `validateURL` 在 proxyBaseUrl 为空时用 `request.getRequestURL()`（受 Host 请求头控制）与 `url` 参数的 host 比对，二者同时填同一任意域名即通过 | proxyBaseUrl 未配置（默认）| 该漏洞的核心绕过点；与 #3（路径技巧）配合才构成完整利用 | https://gccybermonks.com/posts/cve-2021-40822/ 、 https://github.com/geoserver/geoserver/blob/2.19.1/src/wfs/src/main/java/org/vfny/geoserver/wfs/servlets/TestWfsPost.java 、 https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40822.yaml |
| 2 | GET 型转发（body 留空） | 服务端对 `url` 发 GET 并把响应体（含状态/内容类型）回显给攻击者——**非盲 SSRF** | 目标可达 | 与 #3 的差异仅在请求方法与是否携带 XML 体 | https://gccybermonks.com/posts/cve-2021-40822/ 、 https://github.com/phor3nsic/CVE-2021-40822 |
| 3 | POST 型转发（body 填 XML） | `body` 非空时以 `Content-Type: application/xml` POST 转发 | 可 POST 的内网目标 | 可打内网需 POST 的服务 | https://github.com/geoserver/geoserver/blob/2.19.1/src/wfs/src/main/java/org/vfny/geoserver/wfs/servlets/TestWfsPost.java 、 https://github.com/vulhub/vulhub/blob/master/geoserver/CVE-2021-40822/README.md |
| 4 | Basic 认证注入（username/password） | 两个参数拼接成 `Authorization: Basic base64(user:pass)` 转发给目标 | 需凭据的内网服务 | 参数面独立于 url/body，用于打需认证的内网端点 | https://github.com/geoserver/geoserver/blob/2.19.1/src/wfs/src/main/java/org/vfny/geoserver/wfs/servlets/TestWfsPost.java 、 https://github.com/vulhub/vulhub/blob/master/geoserver/CVE-2021-40822/README.md |
| 5 | `/geoserver` 上下文 + `/../` 路径回根 | 公开 PoC 把 url 写成 `http://host/geoserver/../` 形态（保证带 geoserver 上下文同时归一化指向根路径） | 与 Host 伪造配合 | 路径构造维度的技巧，nuclei/vulhub/phor3nsic 三处一致 | https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40822.yaml 、 https://gccybermonks.com/posts/cve-2021-40822/ |
| 6 | 非 http 协议（file://、ftp://、data://）实测 | 报告者原文明确"尝试 FILE、FTP、DATA 等其他协议，总是同样的错误（被拒绝）"——与源码 `HttpURLConnection` 强转失败一致 | — | **公开资料结论：该端点不能用作文件读取**；file:// 路线在本 CVE 公开资料中是被"证伪"而非"可行"的分支 | https://gccybermonks.com/posts/cve-2021-40822/ 、 https://github.com/geoserver/geoserver/blob/2.19.1/src/wfs/src/main/java/org/vfny/geoserver/wfs/servlets/TestWfsPost.java |
| 7 | 利用场景分型：内网探测 / 云元数据 / 特定栈（PHP+Nginx） | 官方公告把影响归纳为"枚举内网、云环境敏感数据（元数据）"与"对特定目标（如 PHP+Nginx）的 SSRF" | 视内网拓扑 | 目标维度变异，决定测试用例的目的导向 | https://github.com/geoserver/geoserver/security/advisories/GHSA-5gw5-jccf-6hxw 、 https://github.com/geoserver/geoserver/security/advisories/GHSA-68cf-j696-wvv9 |
| 8 | 缓解/修复分型：PROXY_BASE_URL 非空 / web.xml security-constraint 封端点 / 2.24.4+ 移除 servlet | 官方给的三档处置：设置不可覆盖的代理基址；`/TestWfsPost/*` 映射到不存在角色；2.25.2/2.24.4 直接移除该 servlet（Demo 页改浏览器端 JS 实现） | 对应不同版本与部署形态 | 防御侧的三个非等价分支，可用于靶场"防御有效性"对照 | https://github.com/geoserver/geoserver/security/advisories/GHSA-5gw5-jccf-6hxw 、 https://github.com/geoserver/geoserver/security/advisories/GHSA-68cf-j696-wvv9 |

### 4.4 可变异维度评估（公开资料证据）

1. **绕过构造维度**：Host 头任意值（`example.com`/`oast.pro`/`internal`）——phor3nsic PoC、nuclei、vulhub 三方各用了不同 Host 值但同一原理（[PoC](https://github.com/phor3nsic/CVE-2021-40822)、[nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-40822.yaml)、[vulhub](https://github.com/vulhub/vulhub/blob/master/geoserver/CVE-2021-40822/README.md)）；vulhub 甚至把它写成使用提示。
2. **请求方法维度**：GET（body 空）vs POST（body 填值）——源码与公开 PoC 均覆盖。
3. **协议维度**：http(s) 可用；file/ftp/data 被公开实测证伪（[gccybermonks](https://gccybermonks.com/posts/cve-2021-40822/)）——这是四个 CVE 中唯一在公开资料里有明确"负结果记录"的维度，对靶场负向用例设计很有价值。
4. **目标维度**：外网探测验证 vs 内网枚举 vs 云元数据 vs 需认证内网服务（Basic 注入）——官方公告与工具分别体现。
5. **证据通道维度**：响应体回显（非盲，[gccybermonks](https://gccybermonks.com/posts/cve-2021-40822/)）vs OAST 回连（nuclei）——两种判定方式非等价（前者能直接读内网内容，后者只证明请求发生）。
6. **版本/防御维度**：受影响判定并非"版本号一刀切"——validateURL 在 2.18.0 起就存在（本次源码比对），漏洞实际依赖"proxyBaseUrl 未配置 + host 校验可绕过"；官方修复拖到 2.24.4/2.25.2 直接移除组件（[GEOS-10229](https://osgeo-org.atlassian.net/browse/GEOS-10229)）。**"长期无修复、CVE 与 GHSA 双编号、姊妹 CVE 共端点"是本 CVE 资料全景的特殊之处。**

**信息可信度**：GHSA×3、GEOS-10229、官方披露页、源码（官方一手）；gccybermonks 报告者原文与 phor3nsic PoC（一手）；nuclei（verified 模板，一手）；vulhub/Acunetix（复现/库条目，其中 vulhub 的 GHSA 引用有误，已在上文勘误）。

---

## 5. 跨漏洞综合：对"靶场测试用例多样性"的启示

从公开资料看，四个 CVE 都不是"单一固定打法"，每个漏洞在公开生态中都沉淀了**至少四类非等价构造维度**，可直接映射为靶场多样化测试用例的维度表：

| 维度 | JBoss CVE-2017-12149 | Shiro CVE-2016-4437 | OFBiz CVE-2024-45507 | GeoServer CVE-2021-40822 |
|---|---|---|---|---|
| 入口变体 | readonly / JMXInvokerServlet / EJBInvokerServlet / web-console Invoker（jexboss、nuclei） | 同一入口，但"有/无有效登录 cookie"两分支（550 vs 721） | forgotPassword/StatsSinceStart、view/StatsSinceStart、findTemporalExpression×2 + tempExprDecoratorLocation | TestWfsPost（另有姊妹 CVE-2024-29198 共端点） |
| 载荷/链变体 | CC1/3/5/6/7、CC2/4、JBossInterceptors1、Spring、Groovy、Jdk7u21（ysoserial 全家） | CC 系（有依赖）vs CB 无依赖链 vs JRMP 外挂 vs 回显/内存马 | `.execute()` / `Runtime.exec` / 两段式下载执行 / Unicode 转义 / 内存马 | GET vs POST 转发、Basic 注入与否 |
| 验证方式变体 | 响应异常特征（ClassCastException） / URLDNS / JRMP 反连 / 落地文件 | deleteMe oracle / SimplePrincipalCollection 原生探测 / DNS 外带 / 回显 | 反弹 shell / 响应 Screen 注释正则 / OAST / 落地文件 | 响应体回显（非盲） / OAST 回连 |
| 前置条件变体 | http-invoker 是否部署、invoker 是否加认证 | key 已知程度（默认/收集/未知）、CBC vs GCM、目标是否出网 | 是否需要 JSESSIONID（公开资料分歧）、目标是否出网可达攻击者 XML | proxyBaseUrl 是否为空、目标内网拓扑 |
| 公开负向记录 | EAP 6/7 不受影响（Bugzilla） | 1.4.2 GCM 后旧封装失效 | 18.12.16 修复后 URL 位置被拒（commit diff） | file/ftp/data 协议被拒（报告者实测） |

**对评测的具体建议（基于以上证据）**：
1. 靶场若只支持每个 CVE 的"vulhub 主线入口 + 单一载荷 + 单一验证通道"，则未覆盖公开生态已证明的 3–4 倍变体空间；上述表格可直接作为用例覆盖度打分表。
2. "检测型与利用型分离"（Shiro 的 URLDNS/SimplePrincipalCollection vs 利用链；JBoss 的 ArrayList 探测 vs CC 链）是公开工具的普遍共识，应作为两类独立用例。
3. "负向用例"（不可用协议、已修复版本行为、错误 key 行为）在公开资料中同样有据可依（GeoServer file:// 证伪、Shiro GCM 分叉、OFBiz 修复 commit 行为），可用于验证靶场判负能力。

---

## 附录 A：抓取失败清单

调研中以下来源多次尝试后仍无法获取正文，均已在正文标注；未因其失败中断调研：

| 来源 | 现象 | 处理 |
|---|---|---|
| https://paper.seebug.org/3228/ | 站点返回 521；Wayback/archive.ph 均 429 | 正文未获取；其结论仅以 vulhub/Threekiii 转引形式收录 |
| https://xz.aliyun.com/t/15569 （重定向 https://xz.aliyun.com/news/15006 ） | 反爬 JS 挑战（瑞数类），静态抓取仅得加密脚本 | 正文未获取 |
| https://mp.weixin.qq.com/s/zUJMt9hdGoz1TEOKy2Cgdg （vulhub jboss 引用的分析文） | 微信验证页 | 正文未获取，仅保留链接 |
| http://blog.knownsec.com/2016/08/apache-shiro-java/ | TLS 连接被重置 | 正文未获取；其在资料体系中的定位以 Java-Deserialization-Cheat-Sheet 收录为准 |
| https://www.bacde.me/post/Apache-Shiro-Deserialize-Vulnerability/ | 抓取超时 | 正文未获取（其观点已由 insightglacier README 转述） |
| https://github.com/advisories/GHSA-w8w4-463p-8pg7 （nuclei OFBiz 模板引用） | 未抓取（GitHub advisory API 限流） | 与 OFBiz 相关的 GHSA 身份**待验证** |
| AabyssZG/ShiroAttack2 | 仓库 404（GitHub API 确认） | 标注待验证，功能以 Ares-X/shiro-exploit 等为准 |
| dottak.me 引用的修复 commit 28f5f87ec9 | 未逐条核对 commit 谱系 | 与 ffb1bc4879 的关系**待验证**（同属 OFBIZ-13132 修复集） |

（完）
