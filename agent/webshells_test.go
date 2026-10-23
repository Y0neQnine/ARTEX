package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// fakeWebshellRecorder 记录被登记的 shell，用于验证工具到存储的那一段。
type fakeWebshellRecorder struct {
	registered []WebshellRecord
	listed     []WebshellSummary
	taskID     int64
	err        error
}

func (f *fakeWebshellRecorder) RegisterWebshell(_ context.Context, in WebshellRecord) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.registered = append(f.registered, in)
	return int64(len(f.registered)), nil
}

func (f *fakeWebshellRecorder) ListWebshells(_ context.Context, taskID int64) ([]WebshellSummary, error) {
	f.taskID = taskID
	if f.err != nil {
		return nil, f.err
	}
	return f.listed, nil
}

func callTool(t *testing.T, tool actool.CoreTool, input string) string {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("%s: call error: %v", tool.Name(), err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}

// TestWebshellToolsAreSeeded 保证两个工具进了内置目录并绑到了对应 agent——
// 没进目录就没有 tools 表行，UI 里勾不到，等于功能没接上。
func TestWebshellToolsAreSeeded(t *testing.T) {
	byKey := map[string]ToolSeed{}
	for _, s := range BuiltinToolSeeds() {
		byKey[s.Key] = s
	}
	reg, ok := byKey["register_webshell"]
	if !ok {
		t.Fatal("register_webshell 没有进入内置工具目录")
	}
	wantAgents := map[string]bool{"worker": false, "mainagent": false}
	for _, a := range reg.Agents {
		if _, want := wantAgents[a]; want {
			wantAgents[a] = true
		}
	}
	for a, got := range wantAgents {
		if !got {
			t.Errorf("register_webshell 未绑定 %s（实际 %v）", a, reg.Agents)
		}
	}
	if reg.Schema == nil {
		t.Error("register_webshell 没有参数 schema")
	}
	if _, ok := byKey["list_webshells"]; !ok {
		t.Fatal("list_webshells 没有进入内置工具目录")
	}
}

// TestRegisterWebshellWithoutHost：宿主没注入存储时（单测 / PG 未连接）必须回
// 一句可读的不可用，而不是 panic —— 工具跑在 harness 自己的 goroutine 上，
// 一个 nil deref 会把整个进程带走。
func TestRegisterWebshellWithoutHost(t *testing.T) {
	ts := NewToolSet(nil, "work-1")
	out := callTool(t, ts.registerWebshell(), `{"url":"http://t/shell.php","shell_type":"php_eval"}`)
	if !strings.Contains(out, "不可用") {
		t.Fatalf("want 不可用 message, got %q", out)
	}
	out = callTool(t, ts.listWebshells(), `{}`)
	if !strings.Contains(out, "不可用") {
		t.Fatalf("list_webshells 未注入时应报不可用, got %q", out)
	}
}

func TestRegisterWebshellPassesFieldsThrough(t *testing.T) {
	rec := &fakeWebshellRecorder{}
	ts := NewToolSet(nil, "work-7")
	ts.SetTaskID(42)
	ts.SetWebshellRecorder(rec)

	out := callTool(t, ts.registerWebshell(), `{"url":"http://10.0.0.5:8080/s.jsp","shell_type":"jsp_runtime","param":"tick","os_type":"linux","name":"上传点 getshell","asset_id":9,"finding_id":11,"intent_id":12}`)
	if !strings.Contains(out, `"webshell_id":1`) {
		t.Fatalf("expected new id in result, got %q", out)
	}
	if len(rec.registered) != 1 {
		t.Fatalf("registered = %d want 1", len(rec.registered))
	}
	got := rec.registered[0]
	if got.URL != "http://10.0.0.5:8080/s.jsp" || got.ShellType != "jsp_runtime" || got.Param != "tick" {
		t.Fatalf("字段透传不完整: %+v", got)
	}
	if got.TaskID != 42 || got.AssetID != 9 || got.FindingID != 11 || got.Worker != "work-7" {
		t.Fatalf("上下文没带上: %+v", got)
	}
}

func TestListWebshellsScopedToTask(t *testing.T) {
	rec := &fakeWebshellRecorder{listed: []WebshellSummary{{ID: 1, URL: "http://a/x.php", Status: "alive"}}}
	ts := NewToolSet(nil, "work-1")
	ts.SetTaskID(7)
	ts.SetWebshellRecorder(rec)

	out := callTool(t, ts.listWebshells(), `{}`)
	if rec.taskID != 7 {
		t.Fatalf("list 应按任务 %d 过滤，实际 %d", 7, rec.taskID)
	}
	if !strings.Contains(out, "http://a/x.php") {
		t.Fatalf("列表未回显已登记的 shell: %q", out)
	}
}

func TestWebshellRecorderSettersReachToolSet(t *testing.T) {
	rec := &fakeWebshellRecorder{}
	w := &Worker{}
	w.SetWebshellRecorder(rec)
	if w.webshellRecorder != rec {
		t.Fatal("Worker.SetWebshellRecorder 没落到字段")
	}
	p := &Planner{}
	p.SetWebshellRecorder(rec)
	if p.webshellRecorder != rec {
		t.Fatal("Planner.SetWebshellRecorder 没落到字段")
	}
	m := &MainAgent{}
	m.SetWebshellRecorder(rec)
	if m.webshellRecorder != rec {
		t.Fatal("MainAgent.SetWebshellRecorder 没落到字段")
	}
}
