package webshell

// 真实 PHP 马 e2e：用本机 php -S 托管生成的冰蝎 / 哥斯拉马，走完整加密往返。
// 默认跳过，显式设置 ARTEX_PHP_E2E=1 才跑；php 路径可用 ARTEX_PHP 指定。
//
// 这是协议层之外最重要的一层：假马只模拟解密，真马会暴露「壳怎么调 payload」
// 这类问题（例如哥斯拉要求 run() 返回字符串而不是直接 echo）。

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealPHPEncryptedShells(t *testing.T) {
	if os.Getenv("ARTEX_PHP_E2E") != "1" {
		t.Skip("set ARTEX_PHP_E2E=1 to run against a real PHP shell")
	}
	php := os.Getenv("ARTEX_PHP")
	if php == "" {
		php = "php"
	}
	if _, err := exec.LookPath(php); err != nil {
		t.Fatalf("php not found: %v", err)
	}

	cases := []struct {
		name     string
		target   *Target
		fileName string
	}{
		{"behinder3 php", &Target{Type: TypeBehinder3PHP, Secret: "e2epass"}, "b3.php"},
		{"behinder4 php aes", &Target{Type: TypeBehinder4PHP, Secret: "e2epass", Crypto: CryptoBehinderAES}, "b4aes.php"},
		{"behinder4 php magic", &Target{Type: TypeBehinder4PHP, Secret: "e2epass", Crypto: CryptoBehinderAESMagic}, "b4magic.php"},
		{"behinder4 php xor-b64", &Target{Type: TypeBehinder4PHP, Secret: "e2epass", Crypto: CryptoBehinderXORB64}, "b4xor.php"},
		{"godzilla4 php", &Target{Type: TypeGodzilla4PHP, Secret: "e2epass", SecretKey: "e2ekey"}, "gz.php"},
		{"artex crypt php", &Target{Type: TypeArtexCryptPHP, Param: "d", Secret: "e2epass"}, "ac.php"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, code, err := Payload(tc.target)
			if err != nil {
				t.Fatalf("Payload: %v", err)
			}
			dir := t.TempDir()
			file := filepath.Join(dir, tc.fileName)
			if err := os.WriteFile(file, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			url, stop := startPHP(t, php, dir, tc.fileName)
			defer stop()
			tc.target.URL = url
			tc.target.InsecureTLS = true

			out, err := Exec(context.Background(), tc.target, "echo artex_e2e_ok", DefaultTimeout)
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if !out.Parsed {
				t.Fatalf("real shell response not parsed: %q", out.Raw)
			}
			if !strings.Contains(out.Output, "artex_e2e_ok") {
				t.Fatalf("unexpected output: %q", out.Output)
			}
			alive, msg, err := Check(context.Background(), tc.target, DefaultTimeout)
			if err != nil || !alive {
				t.Fatalf("Check: alive=%v msg=%q err=%v", alive, msg, err)
			}
		})
	}
}

func startPHP(t *testing.T, php, dir, script string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cmd := exec.Command(php, "-S", addr, "-t", dir)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatalf("start php -S: %v", err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}

	url := "http://" + addr + "/" + script
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			// 再确认脚本可访问（无头请求，马不会执行命令）。
			resp, err := http.Get(url) //nolint:noctx,gosec // 本地测试服务
			if err == nil {
				_ = resp.Body.Close()
				return url, stop
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatalf("php -S did not become ready on %s", addr)
	return "", nil
}
