package agent

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// WebshellRecorder 由宿主注入：worker 在目标上落了一句话马之后，用它把这匹马登记进
// webshells 表，web 端「WebShell」页据此列出、判活并下发命令。
//
// 刻意与 report_finding 分开：漏洞是「目标有问题」，马是「我们已经站住脚」，两者的
// 处置流程、页面与保留策略都不同。实现方负责校验类型/URL 并落库。
type WebshellRecorder interface {
	RegisterWebshell(ctx context.Context, in WebshellRecord) (int64, error)
	// ListWebshells 只读，taskID=0 表示跨任务概览（mainagent 用）。
	ListWebshells(ctx context.Context, taskID int64) ([]WebshellSummary, error)
}

// WebshellRecord 是一次登记请求。
type WebshellRecord struct {
	Name      string
	URL       string
	ShellType string // php_eval | php_assert | php_cmd | jsp_runtime | asp_exec | aspx_exec
	Param     string // 连接参数名（一句话马的口令字段），默认 pass
	OSType    string // linux | windows | "" 自动
	Note      string
	TaskID    int64
	AssetID   int64
	FindingID int64
	Worker    string
}

// WebshellSummary 是列表回显给模型的最小信息（不含马文件内容等实现细节）。
type WebshellSummary struct {
	ID        int64  `json:"id"`
	Name      string `json:"name,omitempty"`
	URL       string `json:"url"`
	ShellType string `json:"shell_type"`
	OSType    string `json:"os_type,omitempty"`
	Status    string `json:"status"`
	Note      string `json:"note,omitempty"`
	TaskID    int64  `json:"task_id,omitempty"`
}

func (t *ToolSet) SetWebshellRecorder(r WebshellRecorder)   { t.webshellRecorder = r }
func (w *Worker) SetWebshellRecorder(r WebshellRecorder)    { w.webshellRecorder = r }
func (p *Planner) SetWebshellRecorder(r WebshellRecorder)   { p.webshellRecorder = r }
func (m *MainAgent) SetWebshellRecorder(r WebshellRecorder) { m.webshellRecorder = r }

// registerWebshellInput 是 register_webshell 的入参。必须带 tag：shell_type / os_type
// 这类下划线键名不会自动匹配 ShellType 这样的字段名，漏 tag 会静默丢掉参数。
type registerWebshellInput struct {
	Name      string          `json:"name"`
	URL       string          `json:"url"`
	ShellType string          `json:"shell_type"`
	Param     string          `json:"param"`
	OSType    string          `json:"os_type"`
	Note      string          `json:"note"`
	AssetID   json.RawMessage `json:"asset_id"`
	FindingID json.RawMessage `json:"finding_id"`
	IntentID  json.RawMessage `json:"intent_id"`
}

// registerWebshell 把「已拿下 shell」这件事写成一条可连接的记录。
func (t *ToolSet) registerWebshell() actool.CoreTool {
	return writeTool("register_webshell",
		"登记目标上已上传/写入的 WebShell（一句话马）。确认拿到 shell 后调用它，web 端「WebShell」页据此展示连接入口、判活并可下发命令——不登记则这条战果只在事实里，页面看不到。"+
			"url 填可访问的马地址；shell_type 按马的实际形态选；param 是马收命令的参数名（默认 pass）；有对应资产/漏洞时带上 asset_id/finding_id 便于回溯。",
		obj(map[string]any{
			"url":        str("马的完整 URL，如 http://target.com/upload/shell.php"),
			"shell_type": str("马类型：php_eval|php_assert|php_cmd|jsp_runtime|asp_exec|aspx_exec"),
			"param":      str("连接参数名（马收命令的字段），默认 pass；php_cmd 默认 cmd"),
			"os_type":    str("目标系统：linux|windows，留空表示由马自身探测"),
			"name":       str("可读名称，如「前台上传点 getshell」"),
			"note":       str("备注：上传路径、口令来源、限制条件等"),
			"asset_id":   idp("可选：该 shell 所在资产 id"),
			"finding_id": idp("可选：对应漏洞（getshell 本身通常是一条 finding）"),
			"intent_id":  idp("可选：产生该 shell 的意图 id，用于回溯链路"),
		}, "url", "shell_type"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a registerWebshellInput
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.webshellRecorder == nil {
				return actool.Errorf("register_webshell 不可用：宿主未注入 WebShell 存储，改为用 record_fact 记录 shell 信息。"), nil
			}
			rec := WebshellRecord{
				Name: a.Name, URL: a.URL, ShellType: a.ShellType, Param: a.Param, OSType: a.OSType,
				Note: a.Note, TaskID: t.taskID, AssetID: pid(a.AssetID), FindingID: pid(a.FindingID),
				Worker: t.worker,
			}
			id, err := t.webshellRecorder.RegisterWebshell(ctx, rec)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := map[string]any{"webshell_id": id, "url": a.URL, "shell_type": a.ShellType}
			if iid := pid(a.IntentID); iid > 0 {
				out["intent_id"] = iid
			}
			return jsonResult(out)
		})
}

// listWebshells 让 planner / mainagent 看到本任务已登记的 shell，避免重复探测、
// 也便于在它基础上规划后续（横向、提权、取证）。
func (t *ToolSet) listWebshells() actool.CoreTool {
	return readTool("list_webshells",
		"列出已登记的 WebShell（id / url / 类型 / 状态）。规划横向与权限保持前先查一次，别重复种马。",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if t.webshellRecorder == nil {
				return actool.Errorf("list_webshells 不可用：宿主未注入 WebShell 存储。"), nil
			}
			list, err := t.webshellRecorder.ListWebshells(ctx, t.taskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"webshells": list, "count": len(list)})
		})
}
