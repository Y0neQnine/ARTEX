"use client";

import * as React from "react";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  FileCodeIcon,
  KeyRoundIcon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  TerminalIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Webshell, WebshellInputPayload, WebshellType } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZES = [25, 50, 100];

// OS 与执行方式的下拉值：留空＝让马自己探测 / 只走命令模式。
const OS_OPTIONS = [
  { value: "", label: "自动" },
  { value: "linux", label: "Linux" },
  { value: "windows", label: "Windows" },
];
const STATUS_OPTIONS = [
  { value: "", label: "全部状态" },
  { value: "alive", label: "存活" },
  { value: "dead", label: "已掉" },
  { value: "unknown", label: "未测" },
];

function fmtTime(ts?: string) {
  if (!ts) return "-";
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function StatusBadge({ status }: { status: string }) {
  if (status === "alive")
    return (
      <Badge variant="secondary" className="text-xs text-emerald-600">
        存活
      </Badge>
    );
  if (status === "dead")
    return (
      <Badge variant="destructive" className="text-xs">
        已掉
      </Badge>
    );
  return (
    <Badge variant="outline" className="text-xs text-muted-foreground">
      未测
    </Badge>
  );
}

// 录入/编辑表单的空壳；id 存在即编辑。
type Draft = WebshellInputPayload & { id?: number };

export default function WebshellsPage() {
  const [webshells, setWebshells] = React.useState<Webshell[]>([]);
  const [types, setTypes] = React.useState<WebshellType[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);

  const [page, setPage] = React.useState(1);
  const [size, setSize] = React.useState(50);
  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [status, setStatus] = React.useState("");
  const [taskFilter, setTaskFilter] = React.useState("");

  // draft 非 null 即打开录入弹窗。
  const [draft, setDraft] = React.useState<Draft | null>(null);
  // consoleShell 非 null 即打开右侧命令面板。
  const [consoleShell, setConsoleShell] = React.useState<Webshell | null>(null);
  const [busyId, setBusyId] = React.useState<number | null>(null);

  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: 改筛选条件时回到第一页是有意为之
  React.useEffect(() => {
    setPage(1);
  }, [queryQ, status, taskFilter, size]);

  React.useEffect(() => {
    api
      .webshellTypes()
      .then(setTypes)
      .catch(() => setTypes([]));
  }, []);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .webshells({
        task: taskFilter || undefined,
        status: status || undefined,
        q: queryQ || undefined,
        page,
        size,
      })
      .then((r) => {
        setWebshells(r.webshells ?? []);
        setTotal(r.total ?? 0);
      })
      .catch((e: Error) => toast.error(`加载 WebShell 列表失败：${e.message}`))
      .finally(() => setLoading(false));
  }, [taskFilter, status, queryQ, page, size]);

  React.useEffect(load, [load]);

  const totalPages = Math.max(1, Math.ceil(total / size));
  const rangeStart = total === 0 ? 0 : (page - 1) * size + 1;
  const rangeEnd = (page - 1) * size + webshells.length;

  // 判活：成功后用返回的最新行原位替换，避免整表刷新丢掉滚动位置。
  async function checkOne(w: Webshell) {
    setBusyId(w.id);
    try {
      const r = await api.checkWebshell(w.id);
      if (r.status) setWebshells((prev) => prev.map((x) => (x.id === w.id ? r.status : x)));
      if (r.alive) toast.success(`${w.url} 存活`);
      else toast.error(`不可连接：${r.error || r.output || "无回显"}`);
    } catch (e) {
      toast.error(`判活失败：${(e as Error).message}`);
    } finally {
      setBusyId(null);
    }
  }

  async function removeOne(w: Webshell) {
    if (!window.confirm(`删除 ${w.url}？只删记录，不会动目标上的马文件。`)) return;
    try {
      await api.deleteWebshell(w.id);
      setWebshells((prev) => prev.filter((x) => x.id !== w.id));
      setTotal((n) => Math.max(0, n - 1));
      if (consoleShell?.id === w.id) setConsoleShell(null);
      toast.success("已删除记录");
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  async function saveDraft(payload: Draft) {
    try {
      if (payload.id) {
        const { id, ...rest } = payload;
        const updated = await api.updateWebshell(id, rest);
        setWebshells((prev) => prev.map((x) => (x.id === id ? updated : x)));
        toast.success("已保存");
      } else {
        const created = await api.createWebshell(payload);
        setWebshells((prev) => [created, ...prev]);
        setTotal((n) => n + 1);
        toast.success("已录入 WebShell");
      }
      setDraft(null);
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <KeyRoundIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">WebShell</h1>
          <Badge variant="secondary">{total}</Badge>
          <span className="text-xs text-muted-foreground">agent 用 register_webshell 登记的马会直接出现在这里</span>
        </div>
        <Button size="sm" className="h-8" onClick={() => setDraft({ shell_type: types[0]?.type ?? "php_eval" })}>
          <PlusIcon className="size-4" />
          录入
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="搜索名称 / URL / 备注..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-8 pl-8"
          />
        </div>
        <Select value={status || "all"} onValueChange={(v) => setStatus(v === "all" ? "" : v)}>
          <SelectTrigger size="sm" className="w-32">
            <SelectValue placeholder="全部状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            {STATUS_OPTIONS.filter((o) => o.value).map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          placeholder="任务 ID"
          className="h-8 w-28"
          value={taskFilter}
          onChange={(e) => setTaskFilter(e.target.value.replace(/\D/g, ""))}
        />
        <Select value={String(size)} onValueChange={(v) => setSize(Number(v))}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n} / 页
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="icon" className="size-8" onClick={load}>
          <RefreshCwIcon className={cn("size-4", loading && "animate-spin")} />
        </Button>

        <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
          <span className="tabular-nums">
            {rangeStart}–{rangeEnd} / {total}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            <ChevronLeftIcon />
          </Button>
          <span className="tabular-nums">
            {page} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            <ChevronRightIcon />
          </Button>
        </div>
      </div>

      <div className="flex h-[calc(100vh-13rem)] min-h-0 flex-col">
        <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
          <div className="min-h-0 flex-1 overflow-auto">
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-card">
                <TableRow>
                  <TableHead className="w-[150px]">名称</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead className="w-[110px]">类型</TableHead>
                  <TableHead className="w-[70px]">参数</TableHead>
                  <TableHead className="w-[70px]">系统</TableHead>
                  <TableHead className="w-[70px]">状态</TableHead>
                  <TableHead className="w-[90px]">来源</TableHead>
                  <TableHead className="w-[80px]">检测</TableHead>
                  <TableHead className="w-[190px]">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && webshells.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="py-12 text-center">
                      <Loader2Icon className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : webshells.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="py-12 text-center text-sm text-muted-foreground">
                      暂无 WebShell。拿下目标上的马后用「录入」登记，或让 agent 调 register_webshell。
                    </TableCell>
                  </TableRow>
                ) : (
                  webshells.map((w) => (
                    <TableRow
                      key={w.id}
                      className={cn("cursor-pointer", consoleShell?.id === w.id && "bg-accent hover:bg-accent")}
                      onClick={() => setConsoleShell(w)}
                    >
                      <TableCell className="max-w-[150px] truncate text-xs font-medium" title={w.name || w.url}>
                        {w.name || "-"}
                      </TableCell>
                      <TableCell className="max-w-0">
                        <code className="block truncate font-mono text-xs" title={w.url}>
                          {w.url}
                        </code>
                        {w.last_error && (
                          <div className="truncate text-[11px] text-red-600 dark:text-red-400" title={w.last_error}>
                            {w.last_error}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs font-mono">
                          {w.shell_label || w.shell_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{w.param}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{w.os_type || "自动"}</TableCell>
                      <TableCell>
                        <StatusBadge status={w.status} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Badge variant="outline" className="text-[11px]">
                            {w.source === "agent" ? "agent" : "手动"}
                          </Badge>
                          {w.worker && (
                            <span className="truncate text-[11px] font-mono text-muted-foreground">{w.worker}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground tabular-nums">
                        {fmtTime(w.last_check_at)}
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 px-2 text-xs"
                            disabled={busyId === w.id}
                            onClick={() => checkOne(w)}
                          >
                            {busyId === w.id ? (
                              <Loader2Icon className="size-3 animate-spin" />
                            ) : (
                              <RefreshCwIcon className="size-3" />
                            )}
                            判活
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 px-2 text-xs"
                            onClick={() => setConsoleShell(w)}
                          >
                            <TerminalIcon className="size-3" />
                            终端
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            onClick={() => setDraft({ ...w, id: w.id })}
                            title="编辑"
                          >
                            <PencilIcon className="size-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            onClick={() => removeOne(w)}
                            title="删除"
                          >
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </Card>
      </div>

      {draft && (
        <WebshellFormDialog
          draft={draft}
          types={types}
          onOpenChange={(open) => !open && setDraft(null)}
          onSubmit={saveDraft}
        />
      )}

      <Sheet open={consoleShell !== null} onOpenChange={(open) => !open && setConsoleShell(null)}>
        <SheetContent className="w-full! max-w-none! gap-0 p-0 sm:w-[52rem]! sm:max-w-[52rem]!">
          {consoleShell && <WebshellConsole shell={consoleShell} onChanged={(next) => setConsoleShell(next)} />}
        </SheetContent>
      </Sheet>
    </div>
  );
}

// WebshellFormDialog：录入 / 编辑一匹马。类型切换时把参数名回填成该类型默认口令，
// 免得用户改了类型还留着 php 的 pass 去连 jsp。
function WebshellFormDialog({
  draft,
  types,
  onOpenChange,
  onSubmit,
}: {
  draft: Draft;
  types: WebshellType[];
  onOpenChange: (open: boolean) => void;
  onSubmit: (payload: Draft) => void;
}) {
  const [form, setForm] = React.useState<Draft>(draft);
  const [saving, setSaving] = React.useState(false);

  const typeOptions =
    types.length > 0
      ? types
      : [{ type: "php_eval", label: "PHP eval", filename: "", default_param: "pass", code_mode: true, note: "" }];
  const current = typeOptions.find((t) => t.type === (form.shell_type || "php_eval")) ?? typeOptions[0];

  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function chooseType(next: string) {
    const t = typeOptions.find((x) => x.type === next);
    setForm((f) => ({
      ...f,
      shell_type: next,
      param: t?.default_param ?? f.param,
      exec_mode: t?.code_mode ? f.exec_mode : "command",
    }));
  }

  async function submit() {
    if (!form.url?.trim()) return toast.error("请填写马的 URL");
    setSaving(true);
    try {
      onSubmit({ ...form, name: form.name ?? "", param: form.param?.trim() });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{form.id ? "编辑 WebShell" : "录入 WebShell"}</DialogTitle>
          <DialogDescription>登记目标上已存在的一句话马；URL 是浏览器所在服务器能访问到的地址。</DialogDescription>
        </DialogHeader>

        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="ws-name">名称</Label>
            <Input
              id="ws-name"
              value={form.name ?? ""}
              onChange={(e) => set("name", e.target.value)}
              placeholder="前台上传点 getshell"
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ws-url">URL</Label>
            <Input
              id="ws-url"
              value={form.url ?? ""}
              onChange={(e) => set("url", e.target.value)}
              placeholder="http://target/upload/shell.php"
              className="font-mono text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label>类型</Label>
              <Select value={current.type} onValueChange={chooseType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {typeOptions.map((t) => (
                    <SelectItem key={t.type} value={t.type}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {current.note && <p className="font-mono text-[11px] text-muted-foreground">{current.note}</p>}
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ws-param">连接参数名</Label>
              <Input
                id="ws-param"
                value={form.param ?? current.default_param}
                onChange={(e) => set("param", e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label>目标系统</Label>
              <Select value={form.os_type ?? ""} onValueChange={(v) => set("os_type", v)}>
                <SelectTrigger>
                  <SelectValue placeholder="自动" />
                </SelectTrigger>
                <SelectContent>
                  {OS_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>执行方式</Label>
              <Select
                value={form.exec_mode ?? "command"}
                onValueChange={(v) => set("exec_mode", v)}
                disabled={!current.code_mode}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="command">系统命令</SelectItem>
                  <SelectItem value="code">代码执行</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="ws-task">任务 ID</Label>
              <Input
                id="ws-task"
                value={form.task_id ?? ""}
                onChange={(e) => set("task_id", e.target.value ? Number(e.target.value.replace(/\D/g, "")) : undefined)}
                inputMode="numeric"
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ws-asset">资产 ID</Label>
              <Input
                id="ws-asset"
                value={form.asset_id ?? ""}
                onChange={(e) =>
                  set("asset_id", e.target.value ? Number(e.target.value.replace(/\D/g, "")) : undefined)
                }
                inputMode="numeric"
                className="font-mono text-xs"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ws-finding">发现 ID</Label>
              <Input
                id="ws-finding"
                value={form.finding_id ?? ""}
                onChange={(e) =>
                  set("finding_id", e.target.value ? Number(e.target.value.replace(/\D/g, "")) : undefined)
                }
                inputMode="numeric"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ws-note">备注</Label>
            <Textarea
              id="ws-note"
              rows={2}
              value={form.note ?? ""}
              onChange={(e) => set("note", e.target.value)}
              placeholder="上传路径、口令来源、限制条件"
            />
          </div>
          <div className="flex items-start gap-2 text-sm">
            <Checkbox
              id="ws-insecure-tls"
              checked={form.insecure_tls !== false}
              onCheckedChange={(v) => set("insecure_tls", v === true)}
              className="mt-0.5"
            />
            <Label
              htmlFor="ws-insecure-tls"
              className="cursor-pointer text-sm leading-relaxed font-normal text-muted-foreground"
            >
              忽略 HTTPS 证书校验（自签目标常见）
            </Label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={submit} disabled={saving}>
            {saving && <Loader2Icon className="size-4 animate-spin" />}
            保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// WebshellConsole：右侧命令面板 + 马文件预览。一次只发一条命令，输出按行贴回。
function WebshellConsole({ shell, onChanged }: { shell: Webshell; onChanged: (next: Webshell) => void }) {
  const [history, setHistory] = React.useState<{ command: string; output: string; ok: boolean }[]>([]);
  const [cmd, setCmd] = React.useState("");
  const [mode, setMode] = React.useState(shell.exec_mode);
  const [running, setRunning] = React.useState(false);
  const [payload, setPayload] = React.useState<{ filename: string; content: string } | null>(null);
  const [payloadLoading, setPayloadLoading] = React.useState(false);
  const scrollRef = React.useRef<HTMLDivElement>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: 新输出/新马文件都要把面板重新贴到底部
  React.useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [history, payload]);

  async function run() {
    const input = cmd.trim();
    if (!input) return;
    setRunning(true);
    try {
      const r = await api.execWebshell(shell.id, input, mode);
      setHistory((h) => [...h, { command: input, output: r.error ? r.error : r.output, ok: r.ok }]);
      setCmd("");
      if (!r.ok) toast.error("未取到标记包裹的输出——马可能不是本系统生成的协议");
    } catch (e) {
      setHistory((h) => [...h, { command: input, output: (e as Error).message, ok: false }]);
    } finally {
      setRunning(false);
    }
  }

  async function loadPayload() {
    setPayloadLoading(true);
    try {
      setPayload(await api.webshellPayload({ id: shell.id }));
    } catch (e) {
      toast.error(`取马文件失败：${(e as Error).message}`);
    } finally {
      setPayloadLoading(false);
    }
  }

  async function checkAlive() {
    try {
      const r = await api.checkWebshell(shell.id);
      if (r.status) onChanged(r.status);
      else toast.error(`不可连接：${r.error || r.output || "无回显"}`);
    } catch (e) {
      toast.error(`判活失败：${(e as Error).message}`);
    }
  }

  return (
    <>
      <SheetHeader className="border-b px-5 py-4">
        <SheetTitle className="pr-8 text-base">WebShell 终端</SheetTitle>
        <SheetDescription className="break-all font-mono text-xs">{shell.url}</SheetDescription>
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Badge variant="secondary" className="text-xs font-mono">
            {shell.shell_label || shell.shell_type}
          </Badge>
          <Badge variant="outline" className="text-xs font-mono">
            {shell.param}
          </Badge>
          <StatusBadge status={shell.status} />
          <Button variant="outline" size="sm" className="h-7 text-xs" onClick={checkAlive}>
            判活
          </Button>
        </div>
      </SheetHeader>

      <div className="flex min-h-0 flex-1 flex-col">
        <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto bg-muted/40">
          {history.length === 0 ? (
            <div className="p-5 text-sm text-muted-foreground">
              输入命令后回车执行。输出由马以随机标记包裹回传，取不到标记会提示协议不匹配。
            </div>
          ) : (
            <div className="space-y-3 p-4">
              {history.map((h, i) => (
                <div key={i} className="space-y-1">
                  <div className="font-mono text-xs text-muted-foreground">
                    <span className="text-primary">$ </span>
                    {h.command}
                  </div>
                  <pre
                    className={cn(
                      "font-mono text-xs break-all whitespace-pre-wrap",
                      !h.ok && "text-red-600 dark:text-red-400",
                    )}
                  >
                    {h.output || "（空）"}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 border-t px-4 py-3">
          {mode === "code" ? (
            <Textarea
              rows={3}
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) void run();
              }}
              placeholder={`PHP 代码，如 phpinfo();`}
              className="font-mono text-xs"
            />
          ) : (
            <Input
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="id / whoami / ipconfig"
              className="font-mono text-xs"
            />
          )}
          <Select value={mode} onValueChange={setMode}>
            <SelectTrigger size="sm" className="w-28 shrink-0">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="command">命令</SelectItem>
              <SelectItem value="code">代码</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" className="h-8 shrink-0" onClick={run} disabled={running || !cmd.trim()}>
            {running ? <Loader2Icon className="size-4 animate-spin" /> : <TerminalIcon className="size-4" />}
            执行
          </Button>
        </div>

        <div className="border-t px-4 py-3">
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="h-8" onClick={loadPayload} disabled={payloadLoading}>
              {payloadLoading ? <Loader2Icon className="size-4 animate-spin" /> : <FileCodeIcon className="size-4" />}
              马文件
            </Button>
            <span className="text-xs text-muted-foreground">
              与本条记录协议配套的马源码，上传到目标后即可用上面的终端连接
            </span>
          </div>
          {payload && (
            <div className="mt-2 rounded-md border bg-muted/40">
              <div className="flex items-center justify-between gap-2 border-b px-3 py-1.5">
                <code className="font-mono text-xs">{payload.filename}</code>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => {
                      navigator.clipboard
                        .writeText(payload.content)
                        .then(() => toast.success("已复制"))
                        .catch(() => toast.error("复制失败"));
                    }}
                  >
                    <CopyIcon className="size-3" />
                    复制
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => {
                      const blob = new Blob([payload.content], { type: "text/plain;charset=utf-8" });
                      const a = document.createElement("a");
                      a.href = URL.createObjectURL(blob);
                      a.download = payload.filename;
                      a.click();
                      URL.revokeObjectURL(a.href);
                    }}
                  >
                    <DownloadIcon className="size-3" />
                    下载
                  </Button>
                </div>
              </div>
              <pre className="max-h-60 overflow-auto p-3 font-mono text-xs break-all whitespace-pre-wrap">
                {payload.content}
              </pre>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
