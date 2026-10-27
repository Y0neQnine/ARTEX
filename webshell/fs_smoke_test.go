package webshell

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// runSH 在本机的 bash 里执行生成的目标侧脚本，用来提前发现引号/转义类问题。
// 没有 bash（例如纯 Windows CI）时跳过——真实目标上的验证由 Kali 上的 php 马完成。
func runSH(t *testing.T, script string) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	// 脚本经 stdin 交给 bash：本地 Windows 的 32KB 命令行上限比目标 Linux 更紧。
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash failed: %v (stderr: %s)\nscript: %s", err, stderr.String(), script)
	}
	return string(out)
}

func TestFSScriptsAgainstBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := strings.TrimSpace(runSH(t, "mktemp -d"))
	defer runSH(t, "rm -rf -- "+root) //nolint:errcheck

	runSH(t, fmt.Sprintf(`mkdir -p %q %q && printf 'hello' > %q`, root+"/sub", root+"/中文 目录", root+"/sub/a.txt"))
	runSH(t, fmt.Sprintf(`printf '0123456789' > %q`, root+"/中文 目录/带 空格'单引号.txt"))

	// 列目录：条目名走 base64，中文、空格、单引号都不应破坏解析。
	list, err := parseFSEntries(runSH(t, fsListScript(OSLinux, root)))
	if err != nil {
		t.Fatalf("parse list: %v", err)
	}
	byName := map[string]FSEntry{}
	for _, e := range list {
		byName[e.Name] = e
	}
	if e, ok := byName["中文 目录"]; !ok || !e.Dir {
		t.Fatalf("missing dir entry: %+v", list)
	}
	inner, err := parseFSEntries(runSH(t, fsListScript(OSLinux, root+"/中文 目录")))
	if err != nil {
		t.Fatalf("parse inner list: %v", err)
	}
	if len(inner) != 1 || inner[0].Name != "带 空格'单引号.txt" || inner[0].Size != 10 {
		t.Fatalf("missing tricky file entry: %+v", inner)
	}

	// 读文件：base64 回传，内容不能被 shell 转义改动。
	out := strings.TrimSpace(runSH(t, fsReadScript(OSLinux, root+"/sub/a.txt", 1024)))
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil || string(raw) != "hello" {
		t.Fatalf("read: %v %q", err, raw)
	}

	// 超限文件应报 ERROR 而不是截断后当成功。
	if out := runSH(t, fsReadScript(OSLinux, root+"/sub/a.txt", 2)); !strings.HasPrefix(strings.TrimSpace(out), "ERROR:") {
		t.Fatalf("over-limit read should fail loudly: %q", out)
	}

	// 分块写：两块追加 + 落盘，二进制内容（含 NUL）必须原样写回。
	dst := root + "/binary.bin"
	tmp := fsTempPath(OSLinux, dst)
	content := append(bytes.Repeat([]byte("A"), linuxChunkBytes), 0x00, 0x01, 0xff, 'Z')
	enc := base64.StdEncoding.EncodeToString(content)
	chunk := 4 * ((linuxChunkBytes + 2) / 3)
	first := true
	for len(enc) > 0 {
		n := chunk
		if n > len(enc) {
			n = len(enc)
		}
		if out := strings.TrimSpace(runSH(t, fsShAppendScript(tmp, enc[:n], first))); out != "OK" {
			t.Fatalf("append chunk: %q", out)
		}
		enc = enc[n:]
		first = false
	}
	if out := strings.TrimSpace(runSH(t, fsFinishWriteScript(OSLinux, tmp, dst))); out != "OK" {
		t.Fatalf("finish write: %q", out)
	}
	got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(runSH(t, fsReadScript(OSLinux, dst, int64(len(content))+1))))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("binary round-trip mismatch: %v %d vs %d", err, len(got), len(content))
	}

	// 重命名 / 改权限 / 删除。
	if out := strings.TrimSpace(runSH(t, fsRenameScript(OSLinux, dst, root+"/renamed.bin"))); out != "OK" {
		t.Fatalf("rename: %q", out)
	}
	if out := strings.TrimSpace(runSH(t, fsChmodScript(root+"/renamed.bin", "600"))); out != "OK" {
		t.Fatalf("chmod: %q", out)
	}
	if mode := strings.TrimSpace(runSH(t, "stat -c %a "+root+"/renamed.bin")); runtime.GOOS != "windows" && mode != "600" {
		t.Fatalf("chmod did not take effect: %s", mode)
	}
	if out := strings.TrimSpace(runSH(t, fsRemoveScript(OSLinux, root+"/renamed.bin", true))); out != "OK" {
		t.Fatalf("remove: %q", out)
	}

	// 目录不可写时应给出 ERROR 而不是沉默。
	if out := runSH(t, fsListScript(OSLinux, root+"/nope")); !strings.HasPrefix(strings.TrimSpace(out), "ERROR:") {
		t.Fatalf("missing dir should report ERROR, got %q", out)
	}
}
