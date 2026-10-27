package webshell

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeShell 在本地模拟一匹按本包协议实现的马：解析请求参数里的命令与边界标记，
// 回显标记包住的输出，用来验证 Build/Run/Parse 的封包与切分，不触碰任何真实目标。
func fakeShell(t *testing.T, shellType, param string, r *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	form, _ := url.ParseQuery(string(b))
	switch shellType {
	case TypePHPCmd:
		// 裸输出型：没有标记，system() 把命令输出直接打出来。
		return "echo[" + form.Get(param) + "]"
	case TypeJSP, TypeASPX, TypeJSPMemory:
		raw, err := base64.StdEncoding.DecodeString(form.Get(param))
		if err != nil {
			t.Fatalf("decode %s param: %v", shellType, err)
		}
		parts := strings.SplitN(string(raw), "\n", 3)
		if len(parts) != 3 {
			t.Fatalf("%s payload wants 3 newline-separated parts, got %d", shellType, len(parts))
		}
		return parts[0] + "echo[" + parts[2] + "]" + parts[1]
	case TypeJSPMemoryHeader:
		// 触发端在请求头里，请求体应为空。
		if r.Method != "GET" {
			t.Fatalf("header-triggered memory shell should be driven by GET, got %s", r.Method)
		}
		if got := r.ContentLength; got != 0 {
			t.Fatalf("header-triggered request must carry no body, ContentLength=%d", got)
		}
		raw, err := base64.StdEncoding.DecodeString(r.Header.Get(param))
		if err != nil {
			t.Fatalf("decode %s header: %v", shellType, err)
		}
		parts := strings.SplitN(string(raw), "\n", 3)
		if len(parts) != 3 {
			t.Fatalf("%s payload wants 3 newline-separated parts, got %d", shellType, len(parts))
		}
		return parts[0] + "echo[" + parts[2] + "]" + parts[1]
	case TypeASP:
		return form.Get("b") + "echo[" + form.Get(param) + "]" + form.Get("e")
	default: // php_eval / php_assert：送进去的是代码，这里按同样规则回显。
		code := form.Get(param)
		if !strings.Contains(code, "base64_decode(") && shellType != TypePHPCmd {
			t.Fatalf("php payload should carry a base64-wrapped input: %q", code)
		}
		begin, end := phpEchoMarkers(code)
		return begin + "echo[php]" + end
	}
}

// phpEchoMarkers 从生成的 PHP 代码里取出 `echo 'B'.$__o.'E';` 的两个标记，
// 模拟马文件的回显行为。
func phpEchoMarkers(code string) (begin, end string) {
	i := strings.Index(code, "echo '")
	if i < 0 {
		panic("php payload without echo framing: " + code)
	}
	rest := code[i+len("echo '"):]
	begin, rest = rest[:strings.Index(rest, "'")], rest[strings.Index(rest, "'")+1:]
	rest = rest[strings.Index(rest, "'")+1:]
	end = rest[:strings.Index(rest, "'")]
	return begin, end
}

func TestBuildAndParseRoundTrip(t *testing.T) {
	cases := []struct {
		shellType  string
		param      string
		mode       string
		input      string
		wantRaw    bool
		wantMethod string // "" = POST + 表单体
	}{
		{TypePHPEval, "pass", ModeCommand, "id", false, ""},
		{TypePHPEval, "pass", ModeCode, "phpinfo();", false, ""},
		{TypePHPAssert, "x", ModeCommand, "uname -a", false, ""},
		{TypePHPCmd, "cmd", ModeCommand, "whoami", true, ""},
		{TypeJSP, "pass", ModeCommand, "ls -la", false, ""},
		{TypeASP, "pass", ModeCommand, "dir", false, ""},
		{TypeASPX, "pass", ModeCommand, "dir", false, ""},
		{TypeJSPMemory, "pass", ModeCommand, "ls -la", false, ""},
		{TypeJSPMemoryHeader, "X-Token", ModeCommand, "ls -la", false, "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.shellType+"/"+tc.mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(fakeShell(t, tc.shellType, tc.param, r))) //nolint:errcheck
			}))
			defer srv.Close()

			target := &Target{URL: srv.URL, Type: tc.shellType, Param: tc.param}
			p, err := Build(target, tc.mode, tc.input)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if p.Raw != tc.wantRaw {
				t.Fatalf("%s: Raw=%v want %v", tc.shellType, p.Raw, tc.wantRaw)
			}
			wantMethod := tc.wantMethod
			if wantMethod == "" {
				wantMethod = "POST"
			}
			if p.Method != wantMethod {
				t.Fatalf("%s: method=%s want %s", tc.shellType, p.Method, wantMethod)
			}
			if wantMethod == "POST" && p.ContentType != "application/x-www-form-urlencoded" {
				t.Fatalf("unexpected request shape: %+v", p)
			}
			if wantMethod == "GET" && (p.ContentType != "" || p.Header != tc.param) {
				t.Fatalf("header-triggered plan should carry no form body: %+v", p)
			}
			out, err := Run(context.Background(), target, p, DefaultTimeout)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if out.Status != http.StatusOK {
				t.Fatalf("status = %d", out.Status)
			}
			if !out.Parsed {
				t.Fatalf("markers missing in response: %q", out.Raw)
			}
			want := "echo[" + tc.input + "]"
			switch tc.shellType {
			case TypePHPEval, TypePHPAssert:
				want = "echo[php]"
			}
			if out.Output != want {
				t.Fatalf("output = %q want %q", out.Output, want)
			}
		})
	}
}

func TestParseRejectsUnmarkedResponse(t *testing.T) {
	tr := &Target{Type: TypeJSP, Param: "pass"}
	p, err := Build(tr, ModeCommand, "id")
	if err != nil {
		t.Fatal(err)
	}
	// 404 页 / WAF 拦截页里没有我们的标记，必须判为未解析，同时保留原文供排查。
	body, ok := p.Parse("<html><body>404 Not Found</body></html>")
	if ok {
		t.Fatal("expected unmarked response to fail parsing")
	}
	if !strings.Contains(body, "404") {
		t.Fatalf("unparsed response should be returned verbatim: %q", body)
	}
}

func TestParseHandlesMarkerInsideOtherOutput(t *testing.T) {
	tr := &Target{Type: TypeJSP, Param: "pass"}
	p, err := Build(tr, ModeCommand, "id")
	if err != nil {
		t.Fatal(err)
	}
	// 站点自己在马前后输出了别的内容（banner / 警告），仍应切出标记之间的部分。
	got, ok := p.Parse("PHP Warning...\n" + p.begin + "uid=0(root)" + p.end + "\ntrailing")
	if !ok || got != "uid=0(root)" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestCodeModeOnlyForPHP(t *testing.T) {
	for _, typ := range []string{TypeJSP, TypeASP, TypeASPX, TypePHPCmd, TypeJSPMemory, TypeJSPMemoryHeader} {
		if _, err := Build(&Target{Type: typ}, ModeCode, "x"); err != ErrModeNotSupported {
			t.Fatalf("%s: want ErrModeNotSupported, got %v", typ, err)
		}
	}
}

func TestHeaderTriggerRejectsNonTokenHeaderName(t *testing.T) {
	// 头名来自用户填的参数名，带空格/换行会破坏请求行，必须挡在封包阶段。
	for _, bad := range []string{"X Token", "X\nToken", "X:Token"} {
		if _, err := Build(&Target{Type: TypeJSPMemoryHeader, Param: bad}, ModeCommand, "id"); err != ErrBadHeaderName {
			t.Fatalf("header name %q: want ErrBadHeaderName, got %v", bad, err)
		}
	}
	if _, err := Build(&Target{Type: TypeJSPMemoryHeader, Param: "X-Api_Key1"}, ModeCommand, "id"); err != nil {
		t.Fatalf("valid header name rejected: %v", err)
	}
}

func TestBuildValidatesInput(t *testing.T) {
	if _, err := Build(&Target{Type: TypePHPEval}, ModeCommand, "   "); err != ErrEmptyInput {
		t.Fatalf("empty input: want ErrEmptyInput, got %v", err)
	}
	if _, err := Build(&Target{Type: "behinder"}, ModeCommand, "id"); err != ErrUnknownType {
		t.Fatalf("unknown type: want ErrUnknownType, got %v", err)
	}
}

func TestRunRejectsNonHTTPURL(t *testing.T) {
	p, err := Build(&Target{Type: TypeJSP}, ModeCommand, "id")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"file:///etc/passwd", "gopher://127.0.0.1:25", "::: not a url", ""} {
		if _, err := Run(context.Background(), &Target{URL: u, Type: TypeJSP}, p, DefaultTimeout); err == nil {
			t.Fatalf("URL %q should be rejected", u)
		}
	}
}

func TestRunRespectsContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be reached after cancel")
	}))
	defer srv.Close()

	target := &Target{URL: srv.URL, Type: TypeJSP, Param: "pass"}
	p, err := Build(target, ModeCommand, "id")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, target, p, DefaultTimeout); err == nil {
		t.Fatal("cancelled context should abort the request")
	}
}

func TestCheckAgainstFakeShell(t *testing.T) {
	for _, typ := range []string{TypePHPEval, TypePHPAssert, TypePHPCmd, TypeJSP, TypeASP, TypeASPX, TypeJSPMemory, TypeJSPMemoryHeader} {
		t.Run(typ, func(t *testing.T) {
			param := "pass"
			switch typ {
			case TypePHPCmd:
				param = "cmd"
			case TypeJSPMemoryHeader:
				param = "X-Token"
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(fakeShell(t, typ, param, r))) //nolint:errcheck
			}))
			defer srv.Close()

			alive, out, err := Check(context.Background(), &Target{URL: srv.URL, Type: typ, Param: param}, DefaultTimeout)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if !alive {
				t.Fatalf("fake %s shell should be alive, got %q", typ, out)
			}
			if !strings.Contains(out, "echo[") {
				t.Fatalf("unexpected probe output: %q", out)
			}
		})
	}
}

func TestCheckFailsAgainstPlainPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html>not a shell</html>")) //nolint:errcheck
	}))
	defer srv.Close()

	alive, msg, err := Check(context.Background(), &Target{URL: srv.URL, Type: TypeJSP, Param: "pass"}, DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if alive {
		t.Fatal("a plain page must not be reported as a live shell")
	}
	if !strings.Contains(msg, "标记") {
		t.Fatalf("dead-shell message should explain the missing markers: %q", msg)
	}
}

func TestCheckReportsTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close() // 立刻关掉端口，Check 应该拿到连接错误而不是假装成功

	alive, _, err := Check(context.Background(), &Target{URL: addr, Type: TypeJSP}, DefaultTimeout)
	if err == nil {
		t.Fatal("closed target should surface a transport error")
	}
	if alive {
		t.Fatal("transport error is not alive")
	}
}

func TestPayloadEmbedsParam(t *testing.T) {
	for _, d := range Types() {
		t.Run(d.Type, func(t *testing.T) {
			target := &Target{Type: d.Type, Param: "zizz"}
			want := "zizz"
			if d.ParamUnused {
				// 第三方马没有参数名，口令走 secret / secret_key；冰蝎马只嵌派生密钥。
				target.Secret = "zizz"
				target.SecretKey = "kek"
				if d.Family == FamilyGodzilla4 {
					want = key16("kek")
				} else {
					want = key16("zizz")
				}
			}
			name, code, err := Payload(target)
			if err != nil {
				t.Fatalf("Payload(%s): %v", d.Type, err)
			}
			if name == "" || code == "" {
				t.Fatalf("%s: empty payload", d.Type)
			}
			if strings.Contains(name, "__PARAM__") || strings.Contains(code, "__PARAM__") {
				t.Fatalf("%s payload left the param placeholder unsubstituted", d.Type)
			}
			if !strings.Contains(code, want) {
				t.Fatalf("%s payload does not carry the configured secret %q", d.Type, want)
			}
			if d.ParamUnused && d.Family == FamilyGodzilla4 && !strings.Contains(code, "zizz") {
				t.Fatalf("%s payload does not carry the configured pass", d.Type)
			}
		})
	}
}

func TestPayloadRejectsUnknownType(t *testing.T) {
	if _, _, err := Payload(&Target{Type: "behinder"}); err != ErrUnknownType {
		t.Fatalf("want ErrUnknownType, got %v", err)
	}
}

func TestParamFallsBackToTypeDefault(t *testing.T) {
	if got := (&Target{Type: TypeJSP}).param(); got != "pass" {
		t.Fatalf("default param: got %q want pass", got)
	}
	if got := (&Target{Type: TypePHPCmd, Param: "  "}).param(); got != "cmd" {
		t.Fatalf("php_cmd default param: got %q want cmd", got)
	}
	if got := (&Target{Type: TypeJSPMemoryHeader}).param(); !validHeaderName(got) {
		t.Fatalf("header-triggered default param must be a usable header name, got %q", got)
	}
	// 自定义参数名要真的进到请求体里
	p, err := Build(&Target{Type: TypePHPCmd, Param: "kk"}, ModeCommand, "id")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Body, "kk=") {
		t.Fatalf("body should use the configured param: %q", p.Body)
	}
}

func TestDescriptorsAreConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Types() {
		if seen[d.Type] {
			t.Fatalf("duplicate descriptor %s", d.Type)
		}
		seen[d.Type] = true
		if !ValidType(d.Type) {
			t.Fatalf("%s listed but not valid", d.Type)
		}
		if d.Filename == "" || d.DefaultParam == "" || d.Label == "" || d.Note == "" {
			t.Fatalf("%s: descriptor incomplete", d.Type)
		}
	}
	if ValidType("") || ValidType("Behinder") {
		t.Fatal("ValidType should reject unknown and empty types")
	}
}

func TestMarkersAreRandomAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		b, e, err := marker()
		if err != nil {
			t.Fatal(err)
		}
		if seen[b] || seen[e] {
			t.Fatalf("marker reused: %s / %s", b, e)
		}
		seen[b], seen[e] = true, true
		if strings.ContainsAny(b, "=&+'\"%\n\t ") || strings.ContainsAny(e, "=&+'\"%\n\t ") {
			t.Fatalf("marker carries URL/quote-sensitive chars: %q %q", b, e)
		}
	}
}

func TestPHPCommandPayloadTriesFallbacks(t *testing.T) {
	code := phpCmdPayload("id", "BEG", "END")
	for _, fn := range []string{"shell_exec", "system", "passthru", "popen", "base64_decode"} {
		if !strings.Contains(code, fn) {
			t.Fatalf("php command payload should fall back to %s: %s", fn, code)
		}
	}
	if strings.Contains(code, "id") && strings.Contains(code, "shell_exec('id')") {
		t.Fatal("command must not be spliced into the code string — it travels base64-encoded")
	}
}
