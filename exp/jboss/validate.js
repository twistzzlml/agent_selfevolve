// JVM 读取验证：java.io.ObjectInputStream 是否接受（并触发）序列化流
var check = function (path) {
  try {
    var o = new java.io.ObjectInputStream(new java.io.FileInputStream(path));
    var r = o.readObject();
    print("READ_OK " + path + " -> " + r);
  } catch (e) {
    print("READ_DONE " + path + " : " + e);
  }
};
check(arguments[0]);
print("--- /tmp markers ---");
var f = new java.io.File("/tmp");
var a = f.listFiles();
for (var i = 0; i < a.length; i++) print("  " + a[i].getName() + " " + a[i].lastModified());
