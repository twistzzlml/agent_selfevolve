import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

/** RT轮探针：惰性 Translet（静态块空操作）。
 *  用途：定位防御层——若被拦=TemplatesImpl 触发层/字节码层有钩；若放行=链路仍可执行，防御在最终动作层。 */
public class PwnC extends AbstractTranslet {
    static {
        try {
            // 惰性动作：仅读取一个无害系统属性，确保静态块被 JVM 执行且不产生任何副作用
            String t = System.getProperty("java.version");
        } catch (Throwable t) {
            // 静默
        }
    }

    public PwnC() {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) {}

    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d,
                          com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i,
                          com.sun.org.apache.xml.internal.serializer.SerializationHandler h) {}
}
