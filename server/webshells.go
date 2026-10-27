package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/webshell"
)

// WebShell API：列表 / 录入 / 编辑 / 删除 / 判活 / 执行命令 / 取马文件。
//
// 命令执行只在已登录（JWT，见 Handler 里的 requireAuth）后可用，且目标地址由本表
// 记录决定，不接受任意 URL 转发——这条链路本质是「向已授权目标上的马发命令」，
// 与 ARTEX 其余渗透能力同边界（README 的授权范围与免责条款）。
//
// 路由集中在 registerRoutes 里注册，这里只实现 handler。

const (
	maxWebshellRequestBytes = 64 << 10
	maxWebshellURLRunes     = 2048
	maxWebshellNameRunes    = 120
	maxWebshellNoteRunes    = 2000
	// 一条命令的等待上限：马卡在目标上（交互式命令、目标宕机）时到点即断。
	webshellExecTimeout  = 60 * time.Second
	webshellCheckTimeout = 15 * time.Second
	maxWebshellOutBytes  = 1 << 20 // 回传前端的输出上限，1MB
	// 上传一个文件要走「base64 文本 → 脚本 → 分块请求」，请求体留给 8MB 原始内容。
	maxWebshellFSRequestBytes = 12 << 20
)

// webshellDTO 是前后端共用的 WebShell 快照。
type webshellDTO struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	TaskID      *int64 `json:"task_id,omitempty"`
	TaskName    string `json:"task_name,omitempty"`
	AssetID     *int64 `json:"asset_id,omitempty"`
	FindingID   *int64 `json:"finding_id,omitempty"`
	URL         string `json:"url"`
	ShellType   string `json:"shell_type"`
	ShellLabel  string `json:"shell_label"`
	Param       string `json:"param"`
	Crypto      string `json:"crypto,omitempty"`
	Secret      string `json:"secret,omitempty"`
	SecretKey   string `json:"secret_key,omitempty"`
	OSType      string `json:"os_type"`
	ExecMode    string `json:"exec_mode"`
	InsecureTLS bool   `json:"insecure_tls"`
	Status      string `json:"status"`
	LastCheckAt string `json:"last_check_at,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	Source      string `json:"source"`
	Worker      string `json:"worker,omitempty"`
	Note        string `json:"note,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// webshellRequest 覆盖 POST/PATCH 的可写字段；PATCH 只认出现的键（见 apply）。
type webshellRequest struct {
	Name        *string `json:"name"`
	TaskID      *int64  `json:"task_id"`
	AssetID     *int64  `json:"asset_id"`
	FindingID   *int64  `json:"finding_id"`
	URL         *string `json:"url"`
	ShellType   *string `json:"shell_type"`
	Param       *string `json:"param"`
	Crypto      *string `json:"crypto"`
	Secret      *string `json:"secret"`
	SecretKey   *string `json:"secret_key"`
	OSType      *string `json:"os_type"`
	ExecMode    *string `json:"exec_mode"`
	InsecureTLS *bool   `json:"insecure_tls"`
	Note        *string `json:"note"`
}

func webshellLabel(shellType string) string {
	for _, d := range webshell.Types() {
		if d.Type == shellType {
			return d.Label
		}
	}
	return shellType
}

func toWebshellDTO(w *db.DBWebshell) webshellDTO {
	dto := webshellDTO{
		ID:          w.ID,
		Name:        w.Name,
		TaskID:      w.TaskID,
		TaskName:    w.TaskName,
		AssetID:     w.AssetID,
		FindingID:   w.FindingID,
		URL:         w.URL,
		ShellType:   w.ShellType,
		ShellLabel:  webshellLabel(w.ShellType),
		Param:       w.Param,
		Crypto:      w.Crypto,
		Secret:      w.Secret,
		SecretKey:   w.SecretKey,
		OSType:      w.OSType,
		ExecMode:    w.ExecMode,
		InsecureTLS: w.InsecureTLS,
		Status:      w.Status,
		LastError:   w.LastError,
		Source:      w.Source,
		Worker:      w.Worker,
		Note:        w.Note,
		CreatedAt:   w.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   w.UpdatedAt.Format(time.RFC3339),
	}
	if w.LastCheckAt != nil {
		dto.LastCheckAt = w.LastCheckAt.Format(time.RFC3339)
	}
	return dto
}

// validateWebshell 校验落库前的字段；返回可直接写给用户的原因。
func validateWebshell(w *db.DBWebshell) string {
	d, ok := webshell.Lookup(w.ShellType)
	if !ok {
		return "不支持的 WebShell 类型"
	}
	switch w.ExecMode {
	case webshell.ModeCommand, webshell.ModeCode:
	default:
		return "执行方式只能是 command 或 code"
	}
	if w.ExecMode == webshell.ModeCode && w.ShellType != webshell.TypePHPEval && w.ShellType != webshell.TypePHPAssert {
		return "只有 PHP eval / PHP assert 型 WebShell 支持代码执行模式"
	}
	switch w.OSType {
	case "", "linux", "windows":
	default:
		return "系统类型只能是 linux / windows 或留空(自动)"
	}
	if utf8.RuneCountInString(w.Name) > maxWebshellNameRunes {
		return "名称过长"
	}
	if utf8.RuneCountInString(w.Note) > maxWebshellNoteRunes {
		return "备注过长"
	}
	if msg := webshellURLError(w.URL); msg != "" {
		return msg
	}
	if utf8.RuneCountInString(w.Secret) > 128 || utf8.RuneCountInString(w.SecretKey) > 128 {
		return "口令或密钥过长"
	}
	if d.ParamUnused {
		// 加密马不靠普通参数收命令；口令与加密方式的校验见下。
		if c := strings.TrimSpace(w.Crypto); c != "" && !d.HasCrypto(c) {
			return "该类型不支持这个加密方式"
		}
		if webshell.IsEncryptedType(w.ShellType) && strings.TrimSpace(w.Secret) == "" {
			return "连接口令不能为空"
		}
		return ""
	}
	if d.Family == webshell.FamilyArtexCrypt && strings.TrimSpace(w.Secret) == "" {
		return "连接口令不能为空"
	}
	if p := strings.TrimSpace(w.Param); p == "" || !isWebshellParamName(p) {
		return "连接参数名只能包含字母、数字、下划线、点、中划线"
	}
	return ""
}

func webshellURLError(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "URL 格式无效"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "URL 只支持 http/https"
	}
	if u.Host == "" {
		return "URL 缺少主机名"
	}
	if utf8.RuneCountInString(raw) > maxWebshellURLRunes {
		return "URL 过长"
	}
	return ""
}

// isWebshellParamName 限制参数名字符集：它会出现在马文件源码里，不能带引号、
// 分号之类会改写马文件语义的字符。
func isWebshellParamName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func (s *Server) webshellTarget(w *db.DBWebshell) *webshell.Target {
	return &webshell.Target{
		URL:         w.URL,
		Type:        w.ShellType,
		Param:       w.Param,
		OSType:      w.OSType,
		InsecureTLS: w.InsecureTLS,
		Secret:      w.Secret,
		SecretKey:   w.SecretKey,
		Crypto:      w.Crypto,
	}
}

func (s *Server) loadWebshell(w http.ResponseWriter, r *http.Request) (*db.DBWebshell, bool) {
	pg := s.pg(w)
	if pg == nil {
		return nil, false
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "ID 无效")
		return nil, false
	}
	row, err := pg.GetWebshell(id)
	if err != nil {
		if errors.Is(err, db.ErrWebshellNotFound) {
			writeErr(w, http.StatusNotFound, "WebShell 不存在")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return nil, false
	}
	return row, true
}

// listWebshells GET /api/webshells?task=&status=&q=&page=&size=
func (s *Server) listWebshells(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var taskID int64
	if v := r.URL.Query().Get("task"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "task 参数无效")
			return
		}
		taskID = n
	}
	status := r.URL.Query().Get("status")
	if status != "" && !db.ValidWebshellStatus(status) {
		writeErr(w, http.StatusBadRequest, "状态筛选值无效")
		return
	}
	size := atoiDefault(r.URL.Query().Get("size"), 50)
	if size <= 0 || size > 200 {
		size = 50
	}
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	rows, total, err := pg.ListWebshells(taskID, status, r.URL.Query().Get("q"), size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := make([]webshellDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toWebshellDTO(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"webshells": items, "total": total, "page": page, "size": size})
}

// webshellTypes GET /api/webshells/types —— 前端下拉与「生成马文件」用。
func (s *Server) webshellTypes(w http.ResponseWriter, _ *http.Request) {
	items := make([]map[string]any, 0, len(webshell.Types()))
	for _, d := range webshell.Types() {
		items = append(items, map[string]any{
			"type":               d.Type,
			"label":              d.Label,
			"filename":           d.Filename,
			"default_param":      d.DefaultParam,
			"code_mode":          d.CodeMode,
			"note":               d.Note,
			"family":             d.Family,
			"language":           d.Language,
			"param_unused":       d.ParamUnused,
			"cryptos":            d.Cryptos,
			"default_crypto":     d.DefaultCrypto,
			"default_secret":     d.DefaultSecret,
			"default_secret_key": d.DefaultSecretKey,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"types": items})
}

func (s *Server) getWebshell(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadWebshell(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, toWebshellDTO(row))
}

// createWebshell POST /api/webshells —— 人工录入一匹已存在的马。
func (s *Server) createWebshell(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req webshellRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxWebshellRequestBytes)
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	row := &db.DBWebshell{Name: deref(req.Name), URL: deref(req.URL), ShellType: webshell.TypePHPEval,
		Param: "pass", OSType: "", ExecMode: webshell.ModeCommand, InsecureTLS: true}
	if msg := applyWebshellRequest(row, &req, true); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	in := webshellInputFromRow(row, db.WebshellSourceManual, "")
	created, err := pg.CreateWebshell(in)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toWebshellDTO(created))
}

// updateWebshell PATCH /api/webshells/{id} —— 只改出现的字段，检测结果不动。
func (s *Server) updateWebshell(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadWebshell(w, r)
	if !ok {
		return
	}
	var req webshellRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxWebshellRequestBytes)
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := applyWebshellRequest(row, &req, false); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	in := webshellInputFromRow(row, row.Source, row.Worker)
	updated, err := s.m.pg.UpdateWebshell(row.ID, in)
	if err != nil {
		if errors.Is(err, db.ErrWebshellNotFound) {
			writeErr(w, http.StatusNotFound, "WebShell 不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toWebshellDTO(updated))
}

func (s *Server) deleteWebshell(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadWebshell(w, r)
	if !ok {
		return
	}
	if err := s.m.pg.DeleteWebshell(row.ID); err != nil {
		if errors.Is(err, db.ErrWebshellNotFound) {
			writeErr(w, http.StatusNotFound, "WebShell 不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": row.ID})
}

// checkWebshell POST /api/webshells/{id}/check —— 跑一条无害 echo 探测，回写状态。
func (s *Server) checkWebshell(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadWebshell(w, r)
	if !ok {
		return
	}
	alive, out, err := webshell.Check(r.Context(), s.webshellTarget(row), webshellCheckTimeout)
	pg := s.m.pg
	if err != nil {
		_ = pg.SetWebshellStatus(row.ID, db.WebshellDead, err.Error())
		writeJSON(w, http.StatusOK, map[string]any{
			"alive": false, "error": err.Error(), "status": toWebshellDTO(mustReload(pg, row.ID)),
		})
		return
	}
	status := db.WebshellDead
	lastErr := ""
	if alive {
		status = db.WebshellAlive
	} else {
		lastErr = out
	}
	_ = pg.SetWebshellStatus(row.ID, status, lastErr)
	writeJSON(w, http.StatusOK, map[string]any{
		"alive": alive, "output": out, "error": lastErr, "status": toWebshellDTO(mustReload(pg, row.ID)),
	})
}

// execWebshell POST /api/webshells/{id}/exec —— 向目标马下发一条命令（或一段代码）。
//
// mode 省略时沿用该行记录的 exec_mode；一次请求只发一条，超时即断。
func (s *Server) execWebshell(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadWebshell(w, r)
	if !ok {
		return
	}
	var body struct {
		Command *string `json:"command"`
		Mode    string  `json:"mode"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWebshellRequestBytes)
	if err := decode(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	input := deref(body.Command)
	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		mode = row.ExecMode
	}
	if strings.TrimSpace(input) == "" {
		writeErr(w, http.StatusBadRequest, "命令不能为空")
		return
	}
	if mode != webshell.ModeCommand && mode != webshell.ModeCode {
		writeErr(w, http.StatusBadRequest, "执行方式无效")
		return
	}
	target := s.webshellTarget(row)
	var out *webshell.Outcome
	var err error
	if webshell.IsEncryptedType(row.ShellType) {
		out, err = webshell.ExecMode(r.Context(), target, mode, input, webshellExecTimeout)
	} else {
		plan, berr := webshell.Build(target, mode, input)
		if berr != nil {
			msg := "命令构造失败"
			if errors.Is(berr, webshell.ErrModeNotSupported) {
				msg = berr.Error()
			}
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		out, err = webshell.Run(r.Context(), target, plan, webshellExecTimeout)
	}
	if err != nil {
		msg := err.Error()
		if errors.Is(err, webshell.ErrModeNotSupported) || errors.Is(err, webshell.ErrXPayloadTooBig) ||
			errors.Is(err, webshell.ErrXProtocol) || errors.Is(err, webshell.ErrEmptyInput) {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		_ = s.m.pg.SetWebshellStatus(row.ID, db.WebshellDead, msg)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "error": msg, "output": "", "parsed": false,
		})
		return
	}
	output := out.Output
	if len(output) > maxWebshellOutBytes {
		output = output[:maxWebshellOutBytes] + "\n…（输出超过 1MB 已截断）"
	}
	// 标记缺失＝马不认这套协议（不是马掉了），因此不改写 alive/dead，只提示。
	if out.Parsed {
		_ = s.m.pg.SetWebshellStatus(row.ID, db.WebshellAlive, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": out.Parsed, "output": output, "raw": truncateForUI(out.Raw), "parsed": out.Parsed,
		"http_status": out.Status, "elapsed_ms": out.Elapsed.Milliseconds(),
	})
}

// fsWebshell POST /api/webshells/{id}/fs —— 文件管理统一入口。
//
// 和命令执行一样，目标地址只取自 webshells 表；路径与内容由用户提供，最终以
// base64 嵌进脚本，不参与 shell 拼接。OS 未指定时先探测一次并回写记录。
func (s *Server) fsWebshell(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadWebshell(w, r)
	if !ok {
		return
	}
	var body struct {
		Op         string `json:"op"`
		Path       string `json:"path"`
		From       string `json:"from"`
		To         string `json:"to"`
		ContentB64 string `json:"content_b64"`
		Mode       string `json:"mode"`
		Recursive  bool   `json:"recursive"`
		OS         string `json:"os"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWebshellFSRequestBytes)
	if err := decode(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	target := s.webshellTarget(row)
	os := row.OSType
	if v := strings.TrimSpace(body.OS); v == webshell.OSLinux || v == webshell.OSWindows {
		os = v
	}
	if os == "" {
		detected, err := webshell.DetectOS(r.Context(), target, webshellExecTimeout)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "自动识别目标系统失败：" + err.Error()})
			return
		}
		os = detected
		_ = s.m.pg.SetWebshellOS(row.ID, os)
	}

	start := time.Now()
	resp := map[string]any{"ok": true, "os": os}
	var opErr error
	switch strings.TrimSpace(body.Op) {
	case webshell.FsList:
		res, err := webshell.List(r.Context(), target, os, body.Path, webshellExecTimeout)
		opErr = err
		if err == nil {
			resp["data"] = res
		}
	case webshell.FsRead:
		if strings.TrimSpace(body.Path) == "" {
			writeErr(w, http.StatusBadRequest, "请提供文件路径")
			return
		}
		var res *webshell.FSRead
		res, opErr = webshell.Read(r.Context(), target, os, body.Path, webshell.DefaultReadLimit, webshellExecTimeout)
		if opErr == nil {
			resp["data"] = map[string]any{
				"path":        res.Path,
				"size":        res.Size,
				"content_b64": base64.StdEncoding.EncodeToString(res.Data),
			}
		}
	case webshell.FsWrite:
		if strings.TrimSpace(body.Path) == "" {
			writeErr(w, http.StatusBadRequest, "请提供文件路径")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(body.ContentB64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "content_b64 不是合法的 base64")
			return
		}
		opErr = webshell.Write(r.Context(), target, os, body.Path, raw, webshellExecTimeout)
		if opErr == nil {
			resp["data"] = map[string]any{"path": webshell.NormalizeFSPath(os, body.Path), "bytes": len(raw)}
		}
	case webshell.FsMkdir:
		if strings.TrimSpace(body.Path) == "" {
			writeErr(w, http.StatusBadRequest, "请提供目录路径")
			return
		}
		opErr = webshell.Mkdir(r.Context(), target, os, body.Path, webshellExecTimeout)
	case webshell.FsDelete:
		if strings.TrimSpace(body.Path) == "" {
			writeErr(w, http.StatusBadRequest, "请提供要删除的路径")
			return
		}
		opErr = webshell.Remove(r.Context(), target, os, body.Path, body.Recursive, webshellExecTimeout)
	case webshell.FsRename:
		if strings.TrimSpace(body.From) == "" || strings.TrimSpace(body.To) == "" {
			writeErr(w, http.StatusBadRequest, "请提供原路径与新路径")
			return
		}
		opErr = webshell.Rename(r.Context(), target, os, body.From, body.To, webshellExecTimeout)
	case webshell.FsChmod:
		if strings.TrimSpace(body.Path) == "" {
			writeErr(w, http.StatusBadRequest, "请提供文件路径")
			return
		}
		opErr = webshell.Chmod(r.Context(), target, os, body.Path, body.Mode, webshellExecTimeout)
	default:
		writeErr(w, http.StatusBadRequest, "不支持的文件操作")
		return
	}
	if opErr != nil {
		resp["ok"] = false
		resp["error"] = opErr.Error()
	}
	resp["elapsed_ms"] = time.Since(start).Milliseconds()
	writeJSON(w, http.StatusOK, resp)
}

// webshellPayload 返回与该记录协议配套的马文件，供复制/下载后上传到目标。
//
// 两种入口共用：GET /api/webshells/{id}/payload（按已落库的配置生成）与
// GET /api/webshells/payload?type=&param=（录入前先预览）。
func (s *Server) webshellPayload(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	target := &webshell.Target{
		Type:      strings.TrimSpace(q.Get("type")),
		Param:     strings.TrimSpace(q.Get("param")),
		Crypto:    strings.TrimSpace(q.Get("crypto")),
		Secret:    strings.TrimSpace(q.Get("secret")),
		SecretKey: strings.TrimSpace(q.Get("secret_key")),
	}
	if idArg := r.PathValue("id"); idArg != "" {
		id, err := strconv.ParseInt(idArg, 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, "ID 无效")
			return
		}
		row, err := pg.GetWebshell(id)
		if err != nil {
			if errors.Is(err, db.ErrWebshellNotFound) {
				writeErr(w, http.StatusNotFound, "WebShell 不存在")
			} else {
				writeErr(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		target = s.webshellTarget(row)
	} else if target.Type == "" {
		target.Type = webshell.TypePHPEval
	}
	name, content, err := webshell.Payload(target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"filename": name, "content": content, "shell_type": target.Type})
}

// applyWebshellRequest 把 PATCH/POST 的字段合进 row；create=true 时缺省 URL 视为错误。
// 返回非空字符串即校验失败的原因。
func applyWebshellRequest(row *db.DBWebshell, req *webshellRequest, create bool) string {
	if req.Name != nil {
		row.Name = strings.TrimSpace(*req.Name)
	}
	if req.URL != nil {
		row.URL = strings.TrimSpace(*req.URL)
	} else if create {
		return "URL 不能为空"
	}
	if req.ShellType != nil {
		row.ShellType = strings.TrimSpace(*req.ShellType)
	} else if create && row.ShellType == "" {
		row.ShellType = webshell.TypePHPEval
	}
	if req.Param != nil {
		row.Param = strings.TrimSpace(*req.Param)
	}
	if req.Crypto != nil {
		row.Crypto = strings.TrimSpace(*req.Crypto)
	}
	if req.Secret != nil {
		row.Secret = strings.TrimSpace(*req.Secret)
	}
	if req.SecretKey != nil {
		row.SecretKey = strings.TrimSpace(*req.SecretKey)
	}
	if req.OSType != nil {
		row.OSType = strings.ToLower(strings.TrimSpace(*req.OSType))
	}
	if req.ExecMode != nil {
		row.ExecMode = strings.TrimSpace(*req.ExecMode)
	}
	if req.InsecureTLS != nil {
		row.InsecureTLS = *req.InsecureTLS
	}
	if req.Note != nil {
		row.Note = strings.TrimSpace(*req.Note)
	}
	if req.TaskID != nil {
		v := *req.TaskID
		if v <= 0 {
			row.TaskID = nil
		} else {
			row.TaskID = &v
		}
	}
	if req.AssetID != nil {
		v := *req.AssetID
		if v <= 0 {
			row.AssetID = nil
		} else {
			row.AssetID = &v
		}
	}
	if req.FindingID != nil {
		v := *req.FindingID
		if v <= 0 {
			row.FindingID = nil
		} else {
			row.FindingID = &v
		}
	}
	if d, ok := webshell.Lookup(row.ShellType); ok {
		if row.Param == "" {
			row.Param = d.DefaultParam
		}
		if d.Family == webshell.FamilyArtexCrypt && row.Secret == "" {
			row.Secret = d.DefaultSecret
		}
		if d.ParamUnused {
			if row.Crypto == "" {
				row.Crypto = d.DefaultCrypto
			}
			if row.Secret == "" {
				row.Secret = d.DefaultSecret
			}
			if row.SecretKey == "" {
				row.SecretKey = d.DefaultSecretKey
			}
		}
	}
	if row.ExecMode == "" {
		row.ExecMode = webshell.ModeCommand
	}
	if msg := validateWebshell(row); msg != "" {
		return msg
	}
	return ""
}

func webshellInputFromRow(row *db.DBWebshell, source, worker string) db.WebshellInput {
	in := db.WebshellInput{
		Name: row.Name, TaskID: row.TaskID, AssetID: row.AssetID, FindingID: row.FindingID,
		URL: row.URL, ShellType: row.ShellType, Param: row.Param,
		Crypto: row.Crypto, Secret: row.Secret, SecretKey: row.SecretKey,
		OSType: row.OSType, ExecMode: row.ExecMode, InsecureTLS: &row.InsecureTLS,
		Source: source, Worker: worker, Note: row.Note,
	}
	if source == "" {
		in.Source = db.WebshellSourceManual
	}
	return in
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// webshellRecorder 把 agent 的 register_webshell / list_webshells 接到 webshells 表。
// pg 未连接时返回 nil —— 两个工具会各自报「不可用」，而不是让 worker 崩。
func (s *Server) webshellRecorder() agent.WebshellRecorder {
	if s.m.pg == nil {
		return nil
	}
	return &pgWebshellRecorder{pg: s.m.pg}
}

type pgWebshellRecorder struct{ pg *db.DB }

func (r *pgWebshellRecorder) RegisterWebshell(_ context.Context, in agent.WebshellRecord) (int64, error) {
	row := &db.DBWebshell{
		Name: in.Name, URL: in.URL, ShellType: in.ShellType, Param: in.Param,
		Crypto: in.Crypto, Secret: in.Secret, SecretKey: in.SecretKey,
		OSType: in.OSType, ExecMode: webshell.ModeCommand, InsecureTLS: true, Note: in.Note,
	}
	if row.ShellType == "" {
		row.ShellType = webshell.TypePHPEval
	}
	if in.TaskID > 0 {
		tid := in.TaskID
		row.TaskID = &tid
	}
	if in.AssetID > 0 {
		aid := in.AssetID
		row.AssetID = &aid
	}
	if in.FindingID > 0 {
		fid := in.FindingID
		row.FindingID = &fid
	}
	if msg := applyWebshellRequest(row, &webshellRequest{}, false); msg != "" {
		return 0, errors.New(msg)
	}
	created, err := r.pg.CreateWebshell(webshellInputFromRow(row, db.WebshellSourceAgent, in.Worker))
	if err != nil {
		return 0, err
	}
	return created.ID, nil
}

func (r *pgWebshellRecorder) ListWebshells(_ context.Context, taskID int64) ([]agent.WebshellSummary, error) {
	rows, _, err := r.pg.ListWebshells(taskID, "", "", 200, 0)
	if err != nil {
		return nil, err
	}
	out := make([]agent.WebshellSummary, 0, len(rows))
	for _, w := range rows {
		s := agent.WebshellSummary{ID: w.ID, Name: w.Name, URL: w.URL, ShellType: w.ShellType,
			OSType: w.OSType, Status: w.Status, Note: w.Note}
		if w.TaskID != nil {
			s.TaskID = *w.TaskID
		}
		out = append(out, s)
	}
	return out, nil
}

// mustReload 回读一行以拿到最新的状态字段；失败时退回原行（只是少显示一次检测时间）。
func mustReload(pg *db.DB, id int64) *db.DBWebshell {
	row, err := pg.GetWebshell(id)
	if err != nil {
		return &db.DBWebshell{ID: id}
	}
	return row
}

func truncateForUI(s string) string {
	if len(s) > maxWebshellOutBytes {
		return s[:maxWebshellOutBytes] + "…"
	}
	return s
}
