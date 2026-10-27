#!/usr/bin/env bash
# ARTEX 安装脚本
#   只有二进制 + 本脚本时：直接走「Docker 起 Postgres → 启动二进制」，不碰 Go/Node/git。
#   在完整仓库里运行时：额外提供「① 全部 Docker」选项。
#
# 用法：
#   ./install.sh                          # 同目录下的 artex（或 artex-<版本>-<os>-<arch>）
#   ./install.sh ./artex-0.3.15-linux-amd64
#   ARTEX_PG_PORT=15432 ./install.sh      # 5432 被占用时换端口
#   ARTEX_ADDR=:9000 ./install.sh         # 换监听地址
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
# 没有 TTY（nohup / CI）时按回车默认值处理，不会卡住
ask(){  local p="$1" d="${2:-}" a=""; printf '%s%s: ' "$p" "${d:+ [$d]}" >&2; read -r a || a=""; echo "${a:-$d}"; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# ── docker 环境检测 / 自动安装 ───────────────────
have_docker(){ command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

ensure_docker(){
  if have_docker; then
    ok "docker 可用（$(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//')）"; return
  fi
  if command -v docker >/dev/null 2>&1; then
    die "docker 已安装但连不上 daemon：sudo systemctl start docker；非 root 用户还需 sudo usermod -aG docker \$USER 后重新登录"
  fi
  warn "未检测到 docker"
  case "$(uname -s)" in
    Linux)
      if [ "$(ask '自动安装 Docker? (y/n)' y)" = y ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER" || true
        ok "Docker 安装完成（用户组变更需重新登录后免 sudo）"
        have_docker || die "docker 装好了但当前会话还用不了：重新登录（或 newgrp docker）后再跑一次本脚本"
      else
        die "请自行安装 docker 后重试"
      fi ;;
    Darwin) die "macOS 请先安装并启动 Docker Desktop：https://www.docker.com/products/docker-desktop/" ;;
    MINGW*|MSYS*|CYGWIN*) die "Windows 请先安装并启动 Docker Desktop，然后在 Git Bash 里重跑本脚本" ;;
    *)      die "请自行安装 docker 后重试" ;;
  esac
}

ensure_compose(){
  docker compose version >/dev/null 2>&1 && return
  die "方式①需要 docker compose：Docker Desktop 自带；Linux 装 docker-compose-plugin 后重试（只要二进制部署请选 ②）"
}


# ── ① 全部 Docker（本地构建二开版镜像，不拉上游） ──────
# 读 .env 里的 ARTEX_IMAGE / ARTEX_TAG，缺省 artex:local
image_ref(){
  local name tag
  name="$(sed -n 's|^ARTEX_IMAGE=||p' .env 2>/dev/null | tail -1)"; tag="$(sed -n 's|^ARTEX_TAG=||p' .env 2>/dev/null | tail -1)"
  echo "${name:-artex}:${tag:-local}"
}
# 有预编译二进制就用 Dockerfile（只装工具、放二进制），否则用 Dockerfile.selfbuild 在容器里编译
build_image(){
  local ref arch
  ref="$(image_ref)"; arch="$(uname -m)"
  case "$arch" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
  if [ -f "dist/${arch}/artex" ]; then
    info "检测到预编译二进制 dist/${arch}/artex，用它构建（快）…"
    docker build -t "$ref" .
  else
    info "无预编译二进制，容器内编译前端 + 后端（首次约 10–20 分钟）…"
    docker build -f Dockerfile.selfbuild -t "$ref" .
  fi
  ok "镜像就绪：$ref"
}
install_docker(){
  ensure_docker
  ensure_compose
  if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || true
    local pw key
    pw="$(ask 'Postgres 密码（回车随机生成）' "$(rand)")"
    key="$(ask 'ANTHROPIC_API_KEY（可留空，后续在 UI 配）' '')"
    sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pw}|" .env
    sed -i.bak "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${key}|" .env
    rm -f .env.bak
    ok "已生成 .env（POSTGRES_PASSWORD 已设置）"
  else
    info "沿用已存在的 .env"
  fi
  build_image
  info "启动…"
  docker compose pull postgres || true
  docker compose up -d
  ok "启动完成 → http://localhost:8787"
  info "查看日志：docker compose logs -f artex"
  info "改代码后重新构建：./install.sh 选 ①，或 docker compose up -d --build"
}

# ── ② Docker 起 Postgres + 运行预编译二进制 ────────────
# 不编译：直接用同名目录里的单二进制，数据库交给 docker。
host_os_arch(){
  case "$(uname -s)" in
    Linux)                echo "linux" ;;
    Darwin)               echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) die "不支持的系统：$(uname -s)（Linux/macOS/Windows Git Bash）" ;;
  esac
}
host_arch(){
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "不支持的架构：$(uname -m)" ;;
  esac
}

pick_binary(){
  local want="$1" os arch f
  os="$(host_os_arch)"; arch="$(host_arch)"
  local name=artex suffix=""
  if [ "$os" = windows ]; then name=artex.exe; suffix=".exe"; fi

  local cands=()
  if [ -n "$want" ]; then cands+=( "$want" ); fi
  cands+=( "./$name" )
  shopt -s nullglob
  cands+=( ./artex*"${os}-${arch}"* "dist/${os}-${arch}/${name}" )
  cands+=( release/artex-*"${os}-${arch}"* )
  shopt -u nullglob

  for f in "${cands[@]}"; do
    [ -f "$f" ] || continue
    # release/ 下的文件是仓库内容，不改它的权限位；需要可执行位时复制成 ./artex（已被 .gitignore 忽略）
    if [ ! -x "$f" ]; then
      case "$f" in
        ./artex*) chmod +x "$f" ;;
        *)        cp -f "$f" "./$name" && f="./$name" && chmod +x "$f" ;;
      esac
    fi
    echo "$f"; return
  done
  die "没找到 ${os}/${arch} 的二进制：把 artex-*-${os}-${arch}${suffix} 和本脚本放同一目录，或执行 ./install.sh <二进制路径>"
}

PG_NAME=artex-pg
PG_VOL=artex-pg
PG_PORT="${ARTEX_PG_PORT:-5432}"

pg_container_exists(){ docker ps -a --format '{{.Names}}' | grep -qx "$PG_NAME"; }

start_postgres(){
  local pw
  if pg_container_exists; then
    info "复用已有 Postgres 容器 ${PG_NAME}"
    docker start "$PG_NAME" >/dev/null 2>&1 || die "启动容器失败：看 docker logs ${PG_NAME}"
    PG_PORT="$(docker port "$PG_NAME" 5432/tcp 2>/dev/null | head -1 | sed 's/.*://')"
    PG_PORT="${PG_PORT:-5432}"
    pw="$(sed -n 's/.*"password"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' config.json 2>/dev/null | head -1)"
    [ -n "$pw" ] || pw="$(ask '该容器里 artex 用户的密码' '')"
  else
    if (exec 3<>/dev/tcp/127.0.0.1/"$PG_PORT") 2>/dev/null; then
      die "本机 ${PG_PORT} 端口已被占用：先停掉占用进程，或用 ARTEX_PG_PORT=15432 $0 指定其它端口"
    fi
    pw="$(ask 'Postgres 密码（回车随机生成）' "$(rand)")"
    info "启动 Postgres 容器 ${PG_NAME}（127.0.0.1:${PG_PORT}）…"
    docker image inspect postgres:16-alpine >/dev/null 2>&1 || info "首次运行会拉取 postgres:16-alpine 镜像…"
    docker run -d --name "$PG_NAME" --restart unless-stopped \
      -p "127.0.0.1:${PG_PORT}:5432" \
      -e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=artex \
      -v "${PG_VOL}:/var/lib/postgresql/data" postgres:16-alpine >/dev/null
  fi
  info "等待 Postgres 就绪（新卷会自动 initdb，约 10–30 秒）…"
  local i hits=0
  for i in $(seq 1 90); do
    # 不用 pg_isready：initdb 结束前 docker-entrypoint 会临时起一个只为初始化的服务，
    # 那一刻能应答但马上就关，客户端会收到 unexpected EOF。要求连续 3 次 select 1 成功。
    if docker exec "$PG_NAME" psql -U artex -d artex -tAc 'select 1' >/dev/null 2>&1; then
      hits=$((hits + 1))
      if [ "$hits" -ge 3 ]; then
        ok "Postgres 就绪"
        DB_PASS="$pw"
        return
      fi
    else
      hits=0
    fi
    sleep 1
  done
  die "Postgres 90 秒内未就绪：看 docker logs ${PG_NAME}"
}

# 与 start.sh 同一套退出码约定：0=停止，75=换装/重启后立刻拉起，其它=指数退避重启。
# 页面「一键更新」把新二进制暂存成 artex.new 后正是以 75 退出，靠这层循环完成换装。
CHILD=""
on_signal(){
  trap - INT TERM
  if [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null; then
    kill -TERM "$CHILD" 2>/dev/null || true
    wait "$CHILD" 2>/dev/null || true
  fi
  exit 0
}

run_loop(){
  local bin="$1"; shift
  local rc=0 delay=1
  trap on_signal INT TERM
  while :; do
    "$bin" "$@" &
    CHILD=$!
    rc=0
    wait "$CHILD" || rc=$?
    CHILD=""
    case "$rc" in
      0)  info "进程正常退出，不再拉起"; return 0 ;;
      75) info "收到换装/重启请求，重新拉起…"; delay=1 ;;
      126|127)
          warn "无法执行 ${bin}（退出码 ${rc}）：确认它是当前平台的二进制、且有执行权限"
          return "$rc" ;;
      *)  warn "进程异常退出（退出码 ${rc}），${delay}s 后重启"
          sleep "$delay"
          delay=$((delay * 2)); if [ "$delay" -gt 60 ]; then delay=60; fi ;;
    esac
  done
}

install_local(){
  local want="${1:-}" bin tls_args=() addr_args=()
  bin="$(pick_binary "$want")" || exit 1
  ok "使用二进制：${bin}"
  ensure_docker
  start_postgres

  # config.json 只有 database / skill_dir 两个键；重写时保留原 skill_dir，旧文件先备份
  local skill_dir="" bak=""
  if [ -f config.json ]; then
    skill_dir="$(sed -n 's/.*"skill_dir"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' config.json | head -1)"
    bak="config.json.bak.$(date +%Y%m%d%H%M%S)"
    cp -f config.json "$bak"
    info "已有 config.json 已备份为 ${bak}"
  fi
  local jpw jskill
  jpw="$(printf '%s' "$DB_PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  jskill="$(printf '%s' "$skill_dir" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  {
    printf '{\n  "database": {\n'
    printf '    "host": "127.0.0.1",\n    "port": %s,\n    "user": "artex",\n' "$PG_PORT"
    printf '    "password": "%s",\n    "dbname": "artex",\n    "sslmode": "disable"\n  }' "$jpw"
    if [ -n "$skill_dir" ]; then printf ',\n  "skill_dir": "%s"' "$jskill"; fi
    printf '\n}\n'
  } > config.json
  chmod 600 config.json
  ok "已生成 config.json"

  if [ -f tls/cert.pem ] && [ -f tls/key.pem ]; then
    tls_args=(-tls-cert tls/cert.pem -tls-key tls/key.pem)
    info "检测到 tls/cert.pem + tls/key.pem，以 HTTPS 启动"
  fi
  if [ -n "${ARTEX_ADDR:-}" ]; then addr_args=(-addr "$ARTEX_ADDR"); fi

  local scheme=http shown="${ARTEX_ADDR:-:8787}"
  if [ "${#tls_args[@]}" -gt 0 ]; then scheme=https; fi
  shown="${shown##*:}"
  info "启动…（Ctrl-C 停止；后台常驻用 nohup/setsid，本脚本会按 start.sh 的退出码约定自动重启）"
  info "浏览器打开 ${scheme}://127.0.0.1:${shown} ，首次进入 /setup 设置管理员密码"
  run_loop "$bin" ${addr_args[@]+"${addr_args[@]}"} ${tls_args[@]+"${tls_args[@]}"}
}

# 完整仓库里才有「全部 Docker」这条路；只有二进制 + 本脚本时直接进二进制模式
if [ -f go.mod ] && [ -f docker-compose.yml ]; then
  echo "=============================="
  echo "  ARTEX 安装"
  echo "  1) 全部 Docker 安装"
  echo "  2) Docker 起 Postgres + 运行已编译好的二进制"
  echo "=============================="
  case "$(ask '选择' 2)" in
    1) install_docker ;;
    2) install_local "${1:-}" ;;
    *) die "无效选择" ;;
  esac
else
  install_local "${1:-}"
fi
