package webshell

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runPS 在本机 cmd 里执行生成的目标侧脚本：走 fsCommand 的 -EncodedCommand 形式，
// 顺便验证接近 8KB 的块仍能通过 cmd 的命令行长度限制。
func runPS(t *testing.T, script string) string {
	t.Helper()
	if _, err := exec.LookPath("powershell"); err != nil {
		t.Skip("powershell not available")
	}
	cmd := exec.Command("cmd", "/c", fsCommand(OSWindows, script))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("powershell failed: %v (stderr: %s)\nscript: %s", err, stderr.String(), script)
	}
	return stdout.String()
}

func TestFSScriptsAgainstPowerShell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only")
	}
	root := filepath.Join(t.TempDir(), "artex 中文 '目录'")
	if out := strings.TrimSpace(runPS(t, fsMkdirScript(OSWindows, root))); out != "OK" {
		t.Fatalf("mkdir: %q", out)
	}

	// 单块写满 windowsChunkBytes，编码后的命令已接近 cmd 的 8191 字符上限。
	dst := filepath.Join(root, "big 文件.bin")
	content := append(bytes.Repeat([]byte("A"), windowsChunkBytes), 0x00, 0x01, 0xff, 'Z')
	tmp := fsTempPath(OSWindows, dst)
	enc := base64.StdEncoding.EncodeToString(content)
	chunk := 4 * ((windowsChunkBytes + 2) / 3)
	first := true
	for len(enc) > 0 {
		n := chunk
		if n > len(enc) {
			n = len(enc)
		}
		if out := strings.TrimSpace(runPS(t, fsWinAppendScript(tmp, enc[:n], first))); out != "OK" {
			t.Fatalf("append chunk: %q", out)
		}
		enc = enc[n:]
		first = false
	}
	if out := strings.TrimSpace(runPS(t, fsFinishWriteScript(OSWindows, tmp, dst))); out != "OK" {
		t.Fatalf("finish write: %q", out)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("binary round-trip mismatch: %v %d vs %d", err, len(got), len(content))
	}

	// 列目录：中文、空格、单引号名都要能原样解析回来。
	list, err := parseFSEntries(runPS(t, fsListScript(OSWindows, root)))
	if err != nil {
		t.Fatalf("parse list: %v", err)
	}
	byName := map[string]FSEntry{}
	for _, e := range list {
		byName[e.Name] = e
	}
	if e, ok := byName["big 文件.bin"]; !ok || e.Dir || e.Size != int64(len(content)) || e.MTime == 0 {
		t.Fatalf("bad entry: %+v (all: %+v)", byName["big 文件.bin"], list)
	}

	// 通过脚本读回：base64 回传，内容不能被改字节。
	out := strings.TrimSpace(runPS(t, fsReadScript(OSWindows, dst, int64(len(content)))))
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil || !bytes.Equal(raw, content) {
		t.Fatalf("read script: %v (%d bytes)", err, len(raw))
	}
	if out := runPS(t, fsReadScript(OSWindows, dst, 2)); !strings.HasPrefix(strings.TrimSpace(out), "ERROR:") {
		t.Fatalf("over-limit read should fail loudly: %q", out)
	}

	// 空文件、重命名、删除。
	empty := filepath.Join(root, "empty.txt")
	if out := strings.TrimSpace(runPS(t, fsCreateEmptyScript(OSWindows, empty))); out != "OK" {
		t.Fatalf("empty file: %q", out)
	}
	if fi, err := os.Stat(empty); err != nil || fi.Size() != 0 {
		t.Fatalf("empty file not created: %v", err)
	}
	renamed := filepath.Join(root, "改名 后.bin")
	if out := strings.TrimSpace(runPS(t, fsRenameScript(OSWindows, dst, renamed))); out != "OK" {
		t.Fatalf("rename: %q", out)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("old path should be gone: %v", err)
	}
	if out := strings.TrimSpace(runPS(t, fsRemoveScript(OSWindows, renamed, false))); out != "OK" {
		t.Fatalf("remove: %q", out)
	}
	if out := runPS(t, fsRemoveScript(OSWindows, renamed, false)); !strings.HasPrefix(strings.TrimSpace(out), "ERROR:") {
		t.Fatalf("removing a missing file should report ERROR, got %q", out)
	}

	// Windows 没有 chmod 语义，必须在动目标前就明确拒绝。
	if err := Chmod(context.Background(), nil, OSWindows, renamed, "600", 0); !errors.Is(err, ErrFSWindowsOnly) {
		t.Fatalf("chmod on windows = %v, want ErrFSWindowsOnly", err)
	}
	if out := strings.TrimSpace(runPS(t, fsRemoveScript(OSWindows, root, true))); out != "OK" {
		t.Fatalf("remove dir: %q", out)
	}
}
