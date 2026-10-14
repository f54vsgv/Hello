#!/usr/bin/env bash
# gofile_upload.sh - 交互式上传到 GoFile，上传完回显下载链接
# 两种模式（运行后选）：1) 多文件压缩成一个 .tar.gz 再上传  2) 不压缩直接逐个上传
# 用法:
#   ./gofile_upload.sh                 # 纯交互式选择
#   ./gofile_upload.sh a.txt b.log dir/  # 参数预填 + 还可继续交互追加
# 环境变量(可选):
#   GOFILE_TOKEN      绑定到自己账号，不填就是游客上传
#   GOFILE_FOLDER_ID  上传到指定目录UUID，需配合 TOKEN
#   GOFILE_PROXY      覆盖代理：设为空字符串表示直连，不设置则走环境默认
#   CURL_EXTRA_OPTS   透传额外 curl 参数，如 CURL_EXTRA_OPTS="--http1.1 --retry 2"

set -u
set -o pipefail

PRIMARY_URL="https://upload.gofile.io/uploadfile"
FALLBACK_URL="https://store1.gofile.io/uploadFile"

die() { echo "❌ $*" >&2; exit 1; }
info() { echo "ℹ️  $*"; }
ok() { echo "✅ $*"; }

check_deps() {
    command -v curl >/dev/null 2>&1 || die "没找到 curl，请先安装 (apt install curl / yum install curl)"
    command -v tar >/dev/null 2>&1 || die "没找到 tar"
    command -v du >/dev/null 2>&1 || die "没找到 du"
}

# 去掉拖拽进终端时自带的外层单/双引号，并展开 ~/
normalize_path() {
    local p="$1"
    # 去首尾空格
    p="$(echo "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    # 去一层外层引号
    if [[ ${#p} -ge 2 ]]; then
        if [[ "${p:0:1}" == "'" && "${p: -1}" == "'" ]] || [[ "${p:0:1}" == '"' && "${p: -1}" == '"' ]]; then
            p="${p:1:-1}"
        fi
    fi
    # 展开 ~/ 前缀
    if [[ "$p" == "~/"* ]]; then
        p="$HOME/${p:2}"
    elif [[ "$p" == "~" ]]; then
        p="$HOME"
    fi
    printf '%s' "$p"
}

parse_link() {
    # $1 = json 文本，输出 downloadPage，失败返回非0
    local json="$1" link=""
    if command -v jq >/dev/null 2>&1; then
        link="$(printf '%s' "$json" | jq -r '.data.downloadPage // empty' 2>/dev/null)"
    elif command -v python3 >/dev/null 2>&1; then
        link="$(printf '%s' "$json" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("data",{}).get("downloadPage",""))' 2>/dev/null)"
    else
        link="$(printf '%s' "$json" | grep -o '"downloadPage"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed -E 's/.*"[Dd]ownload[Pp]age"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
    fi
    [[ -n "$link" && "$link" != "null" ]] || return 1
    printf '%s' "$link"
}

do_upload() {
    # $1 = 本地文件路径，$2 = 上传URL；成功输出 JSON 文本
    local file="$1" url="$2" resp curl_code errlog
    errlog="$(mktemp /tmp/gofile_curl_err.XXXXXX 2>/dev/null || echo /tmp/gofile_curl_err.log)"
    local args=()
    args+=(-sS --connect-timeout 15 --retry 1)
    # 代理覆盖：GOFILE_PROXY 为空字符串表示直连(--noproxy '*')，非空则用指定代理；不设置就走环境默认
    if [[ "${GOFILE_PROXY+x}" == "x" ]]; then
        if [[ -z "$GOFILE_PROXY" ]]; then
            args+=(--noproxy '*')
        else
            args+=(-x "$GOFILE_PROXY")
        fi
    fi
    # 额外 curl 参数透传，如：CURL_EXTRA_OPTS="--http1.1 --retry 2"
    # shellcheck disable=SC2206
    [[ -n "${CURL_EXTRA_OPTS:-}" ]] && args+=(${CURL_EXTRA_OPTS})
    args+=(-F "file=@${file}")
    [[ -n "${GOFILE_TOKEN:-}" ]] && args+=(-F "token=${GOFILE_TOKEN}")
    [[ -n "${GOFILE_FOLDER_ID:-}" ]] && args+=(-F "folderId=${GOFILE_FOLDER_ID}")

    # 注意：脚本里不把 stderr 合并进捕获结果，否则报错文本会混进 JSON 导致解析失败。
    # 手动跑单条命令时可以用 curl ... 2>&1 把进度和报错都打到终端。
    resp="$(curl "${args[@]}" "$url" 2>"$errlog")"
    curl_code=$?
    if [[ $curl_code -ne 0 ]]; then
        echo "--- curl 报错 (exit $curl_code) ---" >&2
        cat "$errlog" >&2 || true
        if [[ $curl_code -eq 35 ]]; then
            echo "⚠️  TLS 握手失败：HTTPS 连不上，多半是本机代理/网络问题。" >&2
            echo "   可依次试：1) 检查代理(当前 HTTPS_PROXY=${HTTPS_PROXY:-<未设置>}) 是否正常" >&2
            echo "   2) GOFILE_PROXY='' $0 直连试试  3) curl -v 看握手卡在哪" >&2
        fi
        rm -f "$errlog" 2>/dev/null || true
        return 1
    fi
    rm -f "$errlog" 2>/dev/null || true
    printf '%s' "$resp"
}

# 依次试主/备上传地址，成功输出 JSON
upload_with_fallback() {
    # $1 = 本地文件路径
    local file="$1" resp
    if resp="$(do_upload "$file" "$PRIMARY_URL")"; then
        printf '%s' "$resp"
        return 0
    fi
    echo "⚠️  主上传地址失败，切备用地址 $FALLBACK_URL ..." >&2
    resp="$(do_upload "$file" "$FALLBACK_URL")" || return 1
    printf '%s' "$resp"
}

# ---------------- 主流程 ----------------
check_deps

FILES=()
# 1. 命令行参数预填("$@" 已经由 shell 按空格/引号切好，此处不要再按空格二次切分)
if [[ $# -gt 0 ]]; then
    for a in "$@"; do
        p="$(normalize_path "$a")"
        if [[ -e "$p" ]]; then
            FILES+=("$p")
        else
            # 字面不存在才试 glob(如 *.log)，用 compgen 避免空格路径被误切
            mapfile -t _expanded < <(compgen -G "$p" 2>/dev/null || true)
            matched=0
            for e in "${_expanded[@]:-}"; do
                if [[ -e "$e" ]]; then FILES+=("$e"); matched=1; fi
            done
            [[ $matched -eq 1 ]] || echo "⚠️  跳过不存在的参数: $a" >&2
        fi
    done
fi

echo "========== GoFile 压缩上传 =========="
echo "支持多选：逐个输入/拖入文件或文件夹路径，空行结束。"
echo "特殊命令：ls=查看已选  undo=撤销上一个  q=退出"
echo

while true; do
    read -r -p "添加文件 #$((${#FILES[@]} + 1)) (空行结束): " raw || { echo; break; }
    p="$(normalize_path "$raw")"
    [[ -z "$p" ]] && break
    case "$p" in
        q|quit|exit) echo "已退出，未上传。"; exit 0 ;;
        ls|list)
            if [[ ${#FILES[@]} -eq 0 ]]; then echo "(暂无已选)"; else for i in "${!FILES[@]}"; do printf '  [%d] %s\n' "$((i+1))" "${FILES[$i]}"; done; fi
            continue ;;
        undo)
            if [[ ${#FILES[@]} -gt 0 ]]; then unset "FILES[$((${#FILES[@]}-1))]"; echo "已撤销上一个。"; else echo "(没什么可撤销)"; fi
            continue ;;
    esac
    # 先按字面找，找不到再试 glob 展开(处理 *.log 这种情况，空格路径不受影响)
    if [[ -e "$p" ]]; then
        FILES+=("$p")
        echo "  + 已添加: $p"
    else
        mapfile -t _expanded < <(compgen -G "$p" 2>/dev/null || true)
        added=0
        for e in "${_expanded[@]:-}"; do
            if [[ -e "$e" ]]; then FILES+=("$e"); echo "  + 已添加: $e"; added=1; fi
        done
        [[ $added -eq 0 ]] && echo "⚠️  不存在，跳过: $raw (提示: 路径含空格请直接拖入，不要手动加反斜杠)"
    fi
done

[[ ${#FILES[@]} -gt 0 ]] || die "一个文件都没选，退出。"
echo
echo "已选 ${#FILES[@]} 个："
for i in "${!FILES[@]}"; do printf '  [%d] %s\n' "$((i+1))" "${FILES[$i]}"; done
du -sh -- "${FILES[@]}" 2>/dev/null || du -s "${FILES[@]}"
echo

# 2. 选择上传方式
echo
echo "请选择上传方式："
echo "  1) 先压缩成一个 .tar.gz 再上传（链接只有一个，适合多文件/文件夹）"
echo "  2) 不压缩，直接逐个上传（每个文件一个链接；文件夹会被跳过）"
read -r -p "输入 1/2 [默认 1]: " mode || mode="1"
[[ -z "${mode:-}" ]] && mode="1"

if [[ "$mode" == "2" ]]; then
    # ---- 直接上传模式 ----
    echo
    echo "将直接上传以下 ${#FILES[@]} 个已选项（文件夹会被跳过）："
    for i in "${!FILES[@]}"; do printf '  [%d] %s\n' "$((i+1))" "${FILES[$i]}"; done
    # 挑出可直接上传的文件
    UPFILES=()
    for f in "${FILES[@]}"; do
        if [[ -f "$f" ]]; then
            UPFILES+=("$f")
        else
            echo "⚠️  跳过（不是普通文件，请用模式1压缩上传）: $f" >&2
        fi
    done
    [[ ${#UPFILES[@]} -gt 0 ]] || die "没有可直接上传的文件，改用模式 1 吧。"
    read -r -p "确认上传这 ${#UPFILES[@]} 个文件? [Y/n]: " confirm || confirm="y"
    [[ -z "$confirm" || "$confirm" == [yY]* ]] || { echo "已取消上传。"; exit 0; }
    echo
    OK_LINKS=()
    FAILS=()
    n=0
    for f in "${UPFILES[@]}"; do
        n=$((n+1))
        info "[$n/${#UPFILES[@]}] 正在上传: $f ($(du -h "$f" | cut -f1)) ..."
        if RESP="$(upload_with_fallback "$f")"; then
            echo "服务器返回：$RESP"
            if LINK="$(parse_link "$RESP")"; then
                ok "[$n] 成功: $f"
                echo "   🔗 $LINK"
                OK_LINKS+=("$f|$LINK")
            else
                echo "❌ [$n] 返回异常，没解析到链接: $f" >&2
                FAILS+=("$f")
            fi
        else
            echo "❌ [$n] 上传失败: $f" >&2
            FAILS+=("$f")
        fi
        echo
    done
    echo "=================================="
    ok "直接上传完成：成功 ${#OK_LINKS[@]} 个，失败 ${#FAILS[@]} 个。"
    for item in "${OK_LINKS[@]:-}"; do
        [[ -z "$item" ]] && continue
        echo "📄 ${item%%|*}"
        echo "   🔗 ${item#*|}"
    done
    for f in "${FAILS[@]:-}"; do
        [[ -z "$f" ]] && continue
        echo "❌ 失败: $f"
    done
    echo "=================================="
    exit 0
fi

# ---- 压缩上传模式 ----
# 3. 压缩包名
default_name="backup-$(date +%Y%m%d-%H%M%S).tar.gz"
read -r -p "压缩包名 [默认 $default_name]: " aname || echo
aname="$(echo "${aname:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
[[ -z "${aname:-}" ]] && aname="$default_name"
[[ "$aname" == *.tar.gz ]] || [[ "$aname" == *.tgz ]] || aname="${aname}.tar.gz"
ARCHIVE="$aname"
if [[ -e "$ARCHIVE" ]]; then
    read -r -p "⚠️  $ARCHIVE 已存在，覆盖? [y/N]: " yn || yn="n"
    [[ "$yn" == [yY]* ]] || die "已取消，请换个包名重跑。"
fi

echo
info "正在压缩 -> $ARCHIVE ..."
if ! tar -czf "$ARCHIVE" -- "${FILES[@]}" 2>&1; then
    die "压缩失败，请检查文件权限/路径。"
fi
ok "压缩完成：$(ls -lh "$ARCHIVE" | awk '{print $5}')  $ARCHIVE"
echo

read -r -p "确认上传到 GoFile? [Y/n]: " confirm || confirm="y"
[[ -z "$confirm" || "$confirm" == [yY]* ]] || { echo "已取消上传，压缩包保留在: $ARCHIVE"; exit 0; }

# 4. 上传(主地址失败自动切备用)
echo
info "正在上传(大文件请耐心等待)..."
RESP=""
if ! RESP="$(upload_with_fallback "$ARCHIVE")"; then
    die "上传失败(网络/curl报错见上)。压缩包保留在: $ARCHIVE"
fi

echo "服务器原始返回："
echo "$RESP"
echo

LINK=""
if LINK="$(parse_link "$RESP")"; then
    echo "=================================="
    ok "上传成功！"
    echo "📦 本地压缩包: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
    echo "🔗 下载链接: $LINK"
    echo "=================================="
    # 尝试顺手提取 code 方便记录
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$RESP" | jq -r '"code: \(.data.code // empty)  fileId: \(.data.id // .data.fileId // empty)"' 2>/dev/null || true
    fi
else
    die "上传接口返回异常，没解析到下载链接，上面是原始返回，请检查。压缩包保留在: $ARCHIVE"
fi

echo
read -r -p "是否删除本地压缩包 $ARCHIVE ? [y/N]: " del || del="n"
if [[ "$del" == [yY]* ]]; then
    rm -f -- "$ARCHIVE" && ok "已删除本地压缩包。"
else
    info "本地压缩包保留: $ARCHIVE"
fi
