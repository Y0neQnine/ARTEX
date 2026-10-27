package webshell

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestNormalizeAndParentFSPath(t *testing.T) {
	linux := []struct{ in, norm, parent string }{
		{"", "/", ""},
		{"/", "/", ""},
		{"/var/www", "/var/www", "/var"},
		{"/var/www/", "/var/www/", "/var"},
		{"/var", "/var", "/"},
		{"/a/b/c", "/a/b/c", "/a/b"},
	}
	for _, c := range linux {
		if got := NormalizeFSPath(OSLinux, c.in); got != c.norm {
			t.Fatalf("linux normalize %q = %q want %q", c.in, got, c.norm)
		}
		if got := ParentFSPath(OSLinux, c.in); got != c.parent {
			t.Fatalf("linux parent %q = %q want %q", c.in, got, c.parent)
		}
	}
	win := []struct{ in, norm, parent string }{
		{"", `C:\`, ""},
		{"C:", `C:\`, ""},
		{"C:/Windows", `C:\Windows`, `C:\`},
		{`C:\Windows\`, `C:\Windows\`, `C:\`},
		{`C:\Windows\System32`, `C:\Windows\System32`, `C:\Windows`},
		{`D:\data`, `D:\data`, `D:\`},
	}
	for _, c := range win {
		if got := NormalizeFSPath(OSWindows, c.in); got != c.norm {
			t.Fatalf("windows normalize %q = %q want %q", c.in, got, c.norm)
		}
		if got := ParentFSPath(OSWindows, c.in); got != c.parent {
			t.Fatalf("windows parent %q = %q want %q", c.in, got, c.parent)
		}
	}
}

func TestParseFSEntries(t *testing.T) {
	name := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	linuxOut := strings.Join([]string{
		"d\t4096\t1761420000\t755\t" + name("uploads"),
		"f\t12\t1761420100\t644\t" + name("a b.txt"),
		"l\t0\t1761420200\t777\t" + name("current"),
		"",
	}, "\n")
	entries, err := parseFSEntries(linuxOut)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d: %+v", len(entries), entries)
	}
	if !entries[0].Dir || entries[0].Name != "uploads" || entries[0].Mode != "755" || entries[0].Size != 4096 {
		t.Fatalf("dir entry mismatch: %+v", entries[0])
	}
	if entries[1].Dir || entries[1].Name != "a b.txt" || entries[1].MTime != 1761420100 {
		t.Fatalf("file entry mismatch: %+v", entries[1])
	}

	// Windows 侧第 4 列留空（没有 unix 权限位），第 6 列是链接目标。
	winOut := "d\t0\t1761420000\t\t" + name("Program Files") + "\t\r\n" +
		"l\t0\t1761420001\t\t" + name("link") + "\t" + name(`C:\target`)
	entries, err = parseFSEntries(winOut)
	if err != nil {
		t.Fatalf("windows parse: %v", err)
	}
	if len(entries) != 2 || entries[0].Name != "Program Files" || entries[1].Link != `C:\target` {
		t.Fatalf("windows entries mismatch: %+v", entries)
	}

	if _, err := parseFSEntries("ERROR:目录不存在或不是目录"); err == nil {
		t.Fatal("expected error for ERROR line")
	}
	// 噪声行应被跳过而不是变成空条目。
	entries, err = parseFSEntries("garbage\n\nf\t1\t2\t644\t" + name("x"))
	if err != nil || len(entries) != 1 || entries[0].Name != "x" {
		t.Fatalf("noise handling: %v %+v", err, entries)
	}
}

func TestFSCommandEncoding(t *testing.T) {
	script := "echo hello\nprintf %s '中文'"
	cmd := fsCommand(OSLinux, script)
	const prefix = "printf %s '"
	if !strings.HasPrefix(cmd, prefix) || !strings.HasSuffix(cmd, "' | base64 -d | sh") {
		t.Fatalf("unexpected linux command: %q", cmd)
	}
	enc := strings.TrimSuffix(strings.TrimPrefix(cmd, prefix), "' | base64 -d | sh")
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || string(raw) != script {
		t.Fatalf("linux script round-trip: %v %q", err, raw)
	}

	winCmd := fsCommand(OSWindows, script)
	const wprefix = "powershell -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(winCmd, wprefix) {
		t.Fatalf("unexpected windows command: %q", winCmd)
	}
	raw, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(winCmd, wprefix))
	if err != nil {
		t.Fatalf("decode windows command: %v", err)
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	if got := string(utf16.Decode(u)); got != psUTF8Output+script {
		t.Fatalf("windows script round-trip: %q", got)
	}

	// cmd 的命令行上限是 8191 字符：按 MAX_PATH 附近的临时文件路径（含中文）验证满块仍在上限内。
	part := strings.Repeat("A", 4*((windowsChunkBytes+2)/3))
	longTmp := `C:\` + strings.Repeat(`深 目录\`, 48) + `.artex_up_1.b64`
	if len([]rune(longTmp)) > 260 {
		t.Fatalf("test path is %d chars, over MAX_PATH", len([]rune(longTmp)))
	}
	line := fsCommand(OSWindows, fsWinAppendScript(longTmp, part, true))
	if len(line) >= 8191 {
		t.Fatalf("windows chunk command is %d chars, over cmd.exe limit", len(line))
	}
}

func TestFSScriptsEmbedBase64Paths(t *testing.T) {
	path := `/var/www/中文 目录/'quote'`
	list := fsListScript(OSLinux, path)
	if !strings.Contains(list, base64.StdEncoding.EncodeToString([]byte(path))) {
		t.Fatalf("list script should carry the path as base64: %s", list)
	}
	if strings.Contains(list, path) {
		t.Fatalf("list script leaked the raw path into shell code")
	}
	read := fsReadScript(OSLinux, path, 1024)
	if !strings.Contains(read, "1024") || !strings.Contains(read, base64.StdEncoding.EncodeToString([]byte(path))) {
		t.Fatalf("read script missing limit or path: %s", read)
	}
	win := fsListScript(OSWindows, `C:\中文目录`)
	if !strings.Contains(win, base64.StdEncoding.EncodeToString([]byte(`C:\中文目录`))) {
		t.Fatalf("windows list script should decode path via base64")
	}
}

func TestWriteChunkCount(t *testing.T) {
	// 一块原始字节经 base64 后的字符数必须能被分块循环整除覆盖，不留残余。
	content := strings.Repeat("x", linuxChunkBytes+1)
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	encChunk := 4 * ((linuxChunkBytes + 2) / 3)
	chunks := 0
	for len(enc) > 0 {
		n := encChunk
		if n > len(enc) {
			n = len(enc)
		}
		enc = enc[n:]
		chunks++
	}
	if chunks != 2 {
		t.Fatalf("linux chunking of %d bytes took %d requests, want 2", len(content), chunks)
	}
}
