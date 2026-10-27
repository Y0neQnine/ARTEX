package db

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// DBWebshell is a row in the webshells table: one planted 一句话马 plus the
// connection parameters the web UI / agent need to reach it.
type DBWebshell struct {
	ID              int64
	Name            string
	TaskID          *int64
	AssetID         *int64
	FindingID       *int64
	URL             string
	ShellType       string
	Param           string
	Crypto          string
	Secret          string
	SecretKey       string
	OSType          string
	ExecMode        string
	InsecureTLS     bool
	Status          string
	LastCheckAt     *time.Time
	LastError       string
	Source          string
	Worker          string
	Note            string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	TaskName        string // populated via LEFT JOIN on tasks
	TaskDescription string // populated via LEFT JOIN on tasks
}

// WebShell connectivity states (webshells.status).
const (
	WebshellUnknown = "unknown" // 未检测
	WebshellAlive   = "alive"   // 可连接
	WebshellDead    = "dead"    // 连接失败
)

// ValidWebshellStatus reports whether s is a known connectivity state.
func ValidWebshellStatus(s string) bool {
	switch s {
	case WebshellUnknown, WebshellAlive, WebshellDead:
		return true
	}
	return false
}

// Webshell source values (webshells.source).
const (
	WebshellSourceManual = "manual"
	WebshellSourceAgent  = "agent"
)

var (
	ErrWebshellNotFound = errors.New("webshell 不存在")
	ErrWebshellInvalid  = errors.New("webshell 参数无效")
)

// WebshellInput carries the writable columns for create/update. Pointer fields
// distinguish「不动」from「置空/置 0」on update.
type WebshellInput struct {
	Name        string
	TaskID      *int64
	AssetID     *int64
	FindingID   *int64
	URL         string
	ShellType   string
	Param       string
	Crypto      string
	Secret      string
	SecretKey   string
	OSType      string
	ExecMode    string
	InsecureTLS *bool
	Source      string
	Worker      string
	Note        string
}

const webshellSelectCols = `w.id, w.name, w.task_id, w.asset_id, w.finding_id, w.url, w.shell_type,
	       w.param, w.crypto, w.secret, w.secret_key, w.os_type, w.exec_mode, w.insecure_tls,
	       w.status, w.last_check_at, w.last_error, w.source, w.worker, w.note, w.created_at,
	       w.updated_at, COALESCE(t.name, '') AS task_name, COALESCE(t.description, '') AS task_description`

func scanWebshells(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*DBWebshell, error) {
	var out []*DBWebshell
	for rows.Next() {
		w := &DBWebshell{}
		if err := rows.Scan(&w.ID, &w.Name, &w.TaskID, &w.AssetID, &w.FindingID, &w.URL,
			&w.ShellType, &w.Param, &w.Crypto, &w.Secret, &w.SecretKey, &w.OSType, &w.ExecMode,
			&w.InsecureTLS, &w.Status, &w.LastCheckAt, &w.LastError, &w.Source, &w.Worker,
			&w.Note, &w.CreatedAt, &w.UpdatedAt, &w.TaskName, &w.TaskDescription); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (d *DB) CreateWebshell(in WebshellInput) (*DBWebshell, error) {
	if strings.TrimSpace(in.URL) == "" {
		return nil, ErrWebshellInvalid
	}
	src := in.Source
	if src == "" {
		src = WebshellSourceManual
	}
	// 与 0 号任务/资产区分开：负数与 0 一律存 NULL。
	var id int64
	err := d.QueryRow(
		`INSERT INTO webshells (name, task_id, asset_id, finding_id, url, shell_type, param,
		                       crypto, secret, secret_key, os_type, exec_mode, insecure_tls, source, worker, note)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id`,
		in.Name, nullableID(in.TaskID), nullableID(in.AssetID), nullableID(in.FindingID),
		strings.TrimSpace(in.URL), in.ShellType, in.Param, in.Crypto, in.Secret, in.SecretKey,
		in.OSType, in.ExecMode, in.InsecureTLS == nil || *in.InsecureTLS, src, in.Worker, in.Note,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return d.GetWebshell(id)
}

// nullableID maps 0 to NULL so an unset id never references a nonexistent row.
func nullableID(v *int64) any {
	if v == nil || *v <= 0 {
		return nil
	}
	return *v
}

// pos renders the $N placeholder for the Nth bound argument. Only the index is
// interpolated into SQL — every value still travels as a driver parameter.
func pos(n int) string { return "$" + strconv.Itoa(n) }

func (d *DB) GetWebshell(id int64) (*DBWebshell, error) {
	rows, err := d.Query(
		`SELECT `+webshellSelectCols+` FROM webshells w
		 LEFT JOIN tasks t ON t.id = w.task_id WHERE w.id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanWebshells(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrWebshellNotFound
	}
	return list[0], nil
}

// ListWebshells filters: taskID 0 = 全部；status "" = 全部；q 匹配 name/url/note。
func (d *DB) ListWebshells(taskID int64, status, q string, limit, offset int) ([]*DBWebshell, int, error) {
	var where []string
	var args []any
	if taskID > 0 {
		args = append(args, taskID)
		where = append(where, "w.task_id = "+pos(len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, "w.status = "+pos(len(args)))
	}
	if qq := strings.TrimSpace(q); qq != "" {
		args = append(args, "%"+strings.ToLower(qq)+"%")
		where = append(where, `(lower(w.name) LIKE `+pos(len(args))+` OR lower(w.url) LIKE `+pos(len(args))+` OR lower(w.note) LIKE `+pos(len(args))+`)`)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM webshells w`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, offset)
	rows, err := d.Query(
		`SELECT `+webshellSelectCols+` FROM webshells w
		 LEFT JOIN tasks t ON t.id = w.task_id`+clause+
			` ORDER BY w.id DESC LIMIT `+pos(len(args)-1)+` OFFSET `+pos(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list, err := scanWebshells(rows)
	return list, total, err
}

// UpdateWebshell 只改动 in 里出现的字段（URL/类型/参数等），status/时间戳由
// SetWebshellStatus 单独维护，避免编辑表单把检测结果清掉。
func (d *DB) UpdateWebshell(id int64, in WebshellInput) (*DBWebshell, error) {
	res, err := d.Exec(
		`UPDATE webshells SET name=$1, task_id=$2, asset_id=$3, finding_id=$4, url=$5,
		        shell_type=$6, param=$7, crypto=$8, secret=$9, secret_key=$10,
		        os_type=$11, exec_mode=$12, insecure_tls=$13, note=$14
		 WHERE id=$15`,
		in.Name, nullableID(in.TaskID), nullableID(in.AssetID), nullableID(in.FindingID),
		strings.TrimSpace(in.URL), in.ShellType, in.Param, in.Crypto, in.Secret, in.SecretKey,
		in.OSType, in.ExecMode, in.InsecureTLS == nil || *in.InsecureTLS, in.Note, id)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrWebshellNotFound
	}
	return d.GetWebshell(id)
}

// SetWebshellStatus records a connectivity probe result (status + error + time).
func (d *DB) SetWebshellStatus(id int64, status, errMsg string) error {
	_, err := d.Exec(
		`UPDATE webshells SET status=$1, last_error=$2, last_check_at=now() WHERE id=$3`,
		status, errMsg, id)
	return err
}

// SetWebshellOS 回写探测到的目标系统，避免每次文件操作都再探一次。
func (d *DB) SetWebshellOS(id int64, os string) error {
	_, err := d.Exec(`UPDATE webshells SET os_type=$1 WHERE id=$2`, os, id)
	return err
}

func (d *DB) DeleteWebshell(id int64) error {
	res, err := d.Exec(`DELETE FROM webshells WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrWebshellNotFound
	}
	return nil
}

// DeleteWebshellsByTask is used when a task is hard-deleted: shells stay usable
// after a task archive, but an explicit delete takes them with the task.
func (d *DB) DeleteWebshellsByTask(taskID int64) (int, error) {
	res, err := d.Exec(`DELETE FROM webshells WHERE task_id = $1`, taskID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
