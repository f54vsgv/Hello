#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络服务探测与弱口令检测工具
支持 CIDR /8 /16 /24 扫描，检测 SSH/RDP/MySQL/Redis 服务并进行弱口令尝试。
"""

import argparse
import hashlib
import ipaddress
import logging
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from datetime import datetime
from io import StringIO
from urllib.parse import urlparse

# ---- 第三方库可选导入 ----
try:
    import socks
    PYSOCKS = True
except ImportError:
    PYSOCKS = False

try:
    import paramiko
    PARAMIKO = True
except ImportError:
    PARAMIKO = False

try:
    from impacket.examples import rdp_check
    IMPACKET_RDP = True
except ImportError:
    IMPACKET_RDP = False

# ---- 默认配置 ----
DEFAULT_PORTS = {
    'ssh': 22,
    'rdp': 3389,
    'mysql': 3306,
    'redis': 6379,
}

# 默认 5 个用户名
DEFAULT_USER_DICT = {
    'ssh': ['root', 'admin', 'test', 'ubuntu', 'user'],
    'rdp': ['Administrator', 'admin', 'test', 'user', 'guest'],
    'mysql': ['root', 'admin', 'mysql', 'test', 'dbuser'],
    'redis': [''],
}

# 默认 5 个密码
DEFAULT_PASS_DICT = {
    'ssh': ['123456', 'password', 'admin', 'root', '12345'],
    'rdp': ['123456', 'Password1', 'admin', '12345', 'password'],
    'mysql': ['123456', 'root', 'admin', 'password', 'mysql'],
    'redis': ['', '123456', 'redis', 'password', 'admin'],
}

# 服务识别特征
SERVICE_BANNERS = {
    'ssh': [b'SSH-'],
    'mysql': [b'mysql'],
    'redis': [b'+PONG', b'-NOAUTH', b'-ERR'],
}

BANNER_PROBES = {
    'ssh': b'',
    'mysql': b'',
    'redis': b'PING\r\n',
    'rdp': b'',
}

# 全局停止标志
STOP_FLAG = threading.Event()

# ---- 速率限制器 ----
class TokenBucket:
    def __init__(self, rate):
        self.rate = max(rate, 1)
        self.tokens = float(rate)
        self.last = time.time()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(max(sleep_time, 0))
                self.tokens = 0
            else:
                self.tokens -= 1


# ---- 代理设置 ----
def setup_proxy(proxy_url):
    if not proxy_url:
        return
    if not PYSOCKS:
        print('[!] 未安装 PySocks，代理不会生效。请执行：pip install pysocks')
        return
    parsed = urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    port = parsed.port or 1080
    if scheme in ('socks5', 'socks'):
        ptype = socks.SOCKS5
    elif scheme in ('socks4',):
        ptype = socks.SOCKS4
    elif scheme in ('http', 'https'):
        ptype = socks.HTTP
    else:
        print(f'[!] 不支持的代理协议：{scheme}')
        return
    socks.set_default_proxy(ptype, host, port, rdns=True)
    socket.socket = socks.socksocket
    print(f'[*] 已设置代理：{scheme}://{host}:{port}')


# ---- IP 生成 ----
def iter_subnets(net, new_prefix):
    """流式切分子网，避免一次性产生大量对象。"""
    try:
        for subnet in net.subnets(new_prefix=new_prefix):
            yield subnet
    except ValueError:
        yield net


def generate_tasks(target, services, ports, sample=None, max_hosts=None, full=False):
    """
    流式生成扫描任务。
    /8 和 /16 默认按每个 /24 子网采样，避免内存和连接爆炸。
    """
    net = ipaddress.ip_network(target, strict=False)
    count = 0

    if not full and net.prefixlen <= 16:
        sample_per_subnet = sample if sample is not None else 1
        for subnet in iter_subnets(net, 24):
            hosts = list(subnet.hosts())
            chosen = random.sample(hosts, min(sample_per_subnet, len(hosts)))
            for host in chosen:
                ip = str(host)
                for svc in services:
                    if STOP_FLAG.is_set():
                        return
                    yield ip, svc, ports[svc]
                    count += 1
                    if max_hosts and count >= max_hosts:
                        return
    elif sample is not None and net.prefixlen < 24:
        for subnet in iter_subnets(net, 24):
            hosts = list(subnet.hosts())
            chosen = random.sample(hosts, min(sample, len(hosts)))
            for host in chosen:
                ip = str(host)
                for svc in services:
                    if STOP_FLAG.is_set():
                        return
                    yield ip, svc, ports[svc]
                    count += 1
                    if max_hosts and count >= max_hosts:
                        return
    else:
        hosts = list(net.hosts())
        random.shuffle(hosts)
        for host in hosts:
            ip = str(host)
            for svc in services:
                if STOP_FLAG.is_set():
                    return
                yield ip, svc, ports[svc]
                count += 1
                if max_hosts and count >= max_hosts:
                    return


def estimate_tasks(target, services_count, sample=None, max_hosts=None, full=False):
    """估算任务总数，用于进度显示。"""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except Exception:
        return 0

    if not full and net.prefixlen <= 16:
        sample_per_subnet = sample if sample is not None else 1
        try:
            subnet_count = sum(1 for _ in net.subnets(new_prefix=24))
        except ValueError:
            subnet_count = 1
        host_count = subnet_count * sample_per_subnet
    elif sample is not None and net.prefixlen < 24:
        try:
            subnet_count = sum(1 for _ in net.subnets(new_prefix=24))
        except ValueError:
            subnet_count = 1
        host_count = subnet_count * sample
    else:
        host_count = net.num_addresses - 2
        if host_count < 0:
            host_count = net.num_addresses

    if max_hosts is not None and max_hosts > 0:
        host_count = min(host_count, max_hosts)

    return host_count * services_count


def warn_large_network(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.prefixlen <= 16:
            print(f'[!] 警告：目标 {target} 非常大（约 {net.num_addresses} 个地址）。')
            print(f'    已启用自动采样策略（每个 /24 随机取 1 个主机）。')
            print(f'    如需全量扫描，请添加 --full；如需调整采样数量，请使用 --sample N。')
    except Exception:
        pass


# ---- 端口探测 ----
def probe_port(ip, port, timeout):
    if STOP_FLAG.is_set():
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


def grab_banner(ip, port, probe, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if probe:
            s.send(probe)
        banner = s.recv(1024)
        s.close()
        return banner
    except Exception:
        return b''


def identify_service(service, banner):
    if not banner:
        return service
    patterns = SERVICE_BANNERS.get(service, [])
    for p in patterns:
        if p in banner:
            return service
    if b'SSH-' in banner:
        return 'ssh'
    if b'+PONG' in banner or b'-NOAUTH' in banner or b'-ERR' in banner:
        return 'redis'
    if banner and banner[0:1] == b'\x4a':
        return 'mysql'
    return service


def banner_display(banner_raw):
    """把二进制 banner 转成可读的字符串，避免乱码。"""
    if not banner_raw:
        return ''
    try:
        text = banner_raw.decode('utf-8')
        if all(c.isprintable() or c in ' \t\n\r' for c in text):
            return text.replace('\n', ' ').replace('\r', ' ')[:200]
    except Exception:
        pass
    return 'HEX:' + banner_raw[:100].hex()


# ---- 弱口令尝试：Redis（自己实现 RESP 协议） ----
def redis_brute_raw(ip, port, passwords, timeout):
    results = []
    # 先尝试无密码
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b'PING\r\n')
        resp = s.recv(1024)
        s.close()
        if resp.startswith(b'+PONG'):
            results.append(('', ''))
            return results
        elif b'NOAUTH' not in resp and b'authentication' not in resp.lower():
            return results
    except Exception:
        return results

    # 需要密码时尝试密码列表
    for pwd in passwords:
        if STOP_FLAG.is_set():
            break
        if not pwd:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(f'AUTH {pwd}\r\n'.encode())
            resp = s.recv(1024)
            s.close()
            if resp.startswith(b'+OK'):
                results.append(('', pwd))
                break
        except Exception:
            pass
    return results


# ---- 弱口令尝试：MySQL（自己实现 mysql_native_password 协议） ----
def mysql_read_packet(s):
    try:
        header = s.recv(4)
        if len(header) < 4:
            return None
        length = int.from_bytes(header[:3], 'little')
        seq = header[3]
        payload = b''
        while len(payload) < length:
            chunk = s.recv(length - len(payload))
            if not chunk:
                return None
            payload += chunk
        return payload
    except Exception:
        return None


def mysql_send_packet(s, payload, seq=1):
    length = len(payload)
    header = length.to_bytes(3, 'little') + bytes([seq])
    s.send(header + payload)


def mysql_native_password(password, scramble):
    if not password:
        return b''
    stage1 = hashlib.sha1(password.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(scramble + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def mysql_parse_greeting(payload):
    """解析 MySQL 握手初始化包，返回 salt 和 auth plugin 名。"""
    if not payload or payload[0] != 0x0a:
        return None, None
    pos = payload.find(b'\x00', 1)
    if pos < 0:
        return None, None
    pos += 1
    if pos + 4 > len(payload):
        return None, None
    pos += 4  # thread id
    if pos + 9 > len(payload):
        return None, None
    salt1 = payload[pos:pos + 8]
    pos += 9
    if pos + 2 > len(payload):
        return None, None
    caps_lower = int.from_bytes(payload[pos:pos + 2], 'little')
    pos += 2
    pos += 1  # charset
    pos += 2  # status
    if pos + 2 > len(payload):
        return salt1, 'mysql_native_password'
    caps_upper = int.from_bytes(payload[pos:pos + 2], 'little')
    pos += 2
    caps = caps_lower | (caps_upper << 16)
    if pos >= len(payload):
        return salt1, 'mysql_native_password'
    auth_len = payload[pos]
    pos += 1 + 10  # reserved

    plugin = 'mysql_native_password'
    salt = salt1
    if caps & 0x80000:  # PLUGIN_AUTH
        if auth_len > 8:
            salt2_len = auth_len - 8
            if pos + salt2_len <= len(payload):
                salt2 = payload[pos:pos + salt2_len - 1]  # 去掉结尾 0x00
                salt = salt1 + salt2
                pos += salt2_len
        if pos < len(payload):
            end = payload.find(b'\x00', pos)
            if end > pos:
                plugin = payload[pos:end].decode('utf-8', 'replace')
    return salt, plugin


def mysql_build_auth_packet(user, password, salt, plugin='mysql_native_password'):
    # 基础 capability flags
    caps = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000
    max_packet = 16777215
    charset = 33  # utf8_general_ci
    payload = caps.to_bytes(4, 'little')
    payload += max_packet.to_bytes(4, 'little')
    payload += bytes([charset])
    payload += b'\x00' * 23
    payload += user.encode() + b'\x00'

    if plugin == 'mysql_native_password':
        pwd_hash = mysql_native_password(password, salt)
        payload += bytes([len(pwd_hash)]) + pwd_hash
    else:
        # 其他插件暂不处理
        payload += b'\x00'

    payload += b'mysql_native_password\x00'
    return payload


def mysql_handle_auth_switch(s, payload, user, password, timeout):
    """处理服务器要求切换认证插件的情况。"""
    if not payload or payload[0] != 0xfe:
        return False
    pos = 1
    end = payload.find(b'\x00', pos)
    if end < 0:
        return False
    plugin = payload[pos:end].decode('utf-8', 'replace')
    salt = payload[end + 1:]
    if plugin == 'mysql_native_password':
        pwd_hash = mysql_native_password(password, salt)
        resp = bytes([len(pwd_hash)]) + pwd_hash
        mysql_send_packet(s, resp, seq=3)
        r = mysql_read_packet(s)
        if r and r[0] == 0x00:
            return True
    return False


def mysql_try_login(ip, port, user, password, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        greeting = mysql_read_packet(s)
        if not greeting:
            s.close()
            return False

        salt, plugin = mysql_parse_greeting(greeting)
        if salt is None:
            s.close()
            return False

        auth_payload = mysql_build_auth_packet(user, password, salt, plugin)
        mysql_send_packet(s, auth_payload, seq=1)

        resp = mysql_read_packet(s)
        if not resp:
            s.close()
            return False

        status = resp[0]
        if status == 0x00:
            s.close()
            return True
        elif status == 0xfe:
            if mysql_handle_auth_switch(s, resp, user, password, timeout):
                s.close()
                return True
        s.close()
        return False
    except Exception:
        return False


def mysql_brute_raw(ip, port, users, passwords, timeout):
    results = []
    for user in users:
        if STOP_FLAG.is_set():
            break
        found = False
        for pwd in passwords:
            if STOP_FLAG.is_set():
                break
            if mysql_try_login(ip, port, user, pwd, timeout):
                results.append((user, pwd))
                found = True
            if found:
                break
    return results


# ---- 弱口令尝试：SSH（使用 paramiko，日志已抑制） ----
def ssh_brute(ip, port, users, passwords, timeout):
    if not PARAMIKO:
        return []
    results = []
    for user in users:
        if STOP_FLAG.is_set():
            break
        found = False
        for pwd in passwords:
            if STOP_FLAG.is_set():
                break
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(ip, port=port, username=user, password=pwd, timeout=timeout,
                               banner_timeout=timeout, auth_timeout=timeout,
                               allow_agent=False, look_for_keys=False)
                results.append((user, pwd))
                found = True
            except paramiko.AuthenticationException:
                pass
            except Exception:
                pass
            finally:
                try:
                    client.close()
                except Exception:
                    pass
            if found:
                break
    return results


# ---- 弱口令尝试：RDP（使用 impacket） ----
def rdp_brute_subprocess(ip, port, users, passwords, timeout):
    rdp_bin = shutil.which('impacket-rdp_check') or shutil.which('rdp_check.py')
    if not rdp_bin:
        return None
    results = []
    for user in users:
        if STOP_FLAG.is_set():
            break
        found = False
        for pwd in passwords:
            if STOP_FLAG.is_set():
                break
            target = f'{user}:{pwd}@{ip}:{port}'
            try:
                proc = subprocess.run([rdp_bin, target], timeout=timeout,
                                      capture_output=True, text=True)
                out = proc.stdout + proc.stderr
                if 'Access Granted' in out:
                    results.append((user, pwd))
                    found = True
            except Exception:
                pass
            if found:
                break
    return results


def rdp_brute_inprocess(ip, port, users, passwords, timeout):
    if not IMPACKET_RDP:
        return None
    results = []
    for user in users:
        if STOP_FLAG.is_set():
            break
        found = False
        for pwd in passwords:
            if STOP_FLAG.is_set():
                break
            target = f'{user}:{pwd}@{ip}:{port}'
            old_argv = sys.argv
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.argv = ['rdp_check.py', target]
            sys.stdout = StringIO()
            sys.stderr = StringIO()
            try:
                rdp_check.main()
            except SystemExit:
                pass
            finally:
                out = sys.stdout.getvalue() + sys.stderr.getvalue()
                sys.argv = old_argv
                sys.stdout = old_stdout
                sys.stderr = old_stderr
            if 'Access Granted' in out:
                results.append((user, pwd))
                found = True
            if found:
                break
    return results


def rdp_brute(ip, port, users, passwords, timeout, use_inprocess=False):
    if use_inprocess:
        return rdp_brute_inprocess(ip, port, users, passwords, timeout)
    return rdp_brute_subprocess(ip, port, users, passwords, timeout)


# ---- 单个任务扫描 ----
def scan_task(args, ip, service, port, limiter):
    if STOP_FLAG.is_set():
        return None
    limiter.acquire()
    if not probe_port(ip, port, args.timeout):
        return None

    probe = BANNER_PROBES.get(service, b'')
    banner = grab_banner(ip, port, probe, args.timeout)
    identified = identify_service(service, banner)

    result = {
        'ip': ip,
        'service': service,
        'port': port,
        'banner_raw': banner[:200],
        'banner': banner_display(banner[:200]),
        'identified': identified,
        'credentials': [],
    }

    if args.no_brute:
        return result

    # 对 SSH 先做 banner 校验，避免 paramiko 对非 SSH 服务打印异常堆栈
    if service == 'ssh' and not banner.startswith(b'SSH-'):
        return result

    users = args.user_dict_data.get(service, DEFAULT_USER_DICT.get(service, ['']))
    passwords = args.pass_dict_data.get(service, DEFAULT_PASS_DICT.get(service, ['']))

    if service == 'ssh':
        creds = ssh_brute(ip, port, users, passwords, args.timeout)
    elif service == 'rdp':
        use_inprocess = bool(args.proxy and PYSOCKS and IMPACKET_RDP)
        creds = rdp_brute(ip, port, users, passwords, args.timeout, use_inprocess=use_inprocess)
        if creds is None:
            result['rdp_note'] = 'RDP 弱口令检测需要安装 impacket（pip install impacket）'
            creds = []
    elif service == 'mysql':
        creds = mysql_brute_raw(ip, port, users, passwords, args.timeout)
    elif service == 'redis':
        creds = redis_brute_raw(ip, port, passwords, args.timeout)
    else:
        creds = []

    result['credentials'] = creds
    return result


# ---- 主函数 ----
def parse_service_dict(path):
    data = {}
    if not path or not os.path.exists(path):
        return data
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line:
                continue
            svc, value = line.split(':', 1)
            svc = svc.strip().lower()
            value = value.strip()
            data.setdefault(svc, []).append(value)
    return data


def init_output(path, target, services):
    if not path:
        return
    with open(path, 'w', encoding='utf-8') as f:
        f.write('========================================\n')
        f.write('         网络服务扫描报告\n')
        f.write('========================================\n')
        f.write(f'扫描目标：{target}\n')
        f.write(f'检测服务：{", ".join(services)}\n')
        f.write(f'开始时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write('========================================\n\n')


def print_result(res, print_lock):
    ts = datetime.now().strftime('%H:%M:%S')
    base = f'[{ts}] [{res["service"].upper()}] {res["ip"]}:{res["port"]}'
    lines = []
    if res.get('banner'):
        lines.append(f'{base} 横幅={res["banner"][:80]}')
    else:
        lines.append(f'{base} 端口开放')
    for user, pwd in res['credentials']:
        if res['service'] == 'redis' and not user:
            lines.append(f'  [+] 存在弱口令：无认证 / {pwd if pwd else "空密码"}')
        else:
            lines.append(f'  [+] 存在弱口令：{user}/{pwd}')
    if res.get('rdp_note'):
        lines.append(f'  [!] {res["rdp_note"]}')
    with print_lock:
        for line in lines:
            print(line)


def save_result(res, output_path, output_lock):
    if not output_path:
        return
    with output_lock:
        with open(output_path, 'a', encoding='utf-8') as f:
            f.write(f'[{res["service"].upper()}] {res["ip"]}:{res["port"]}\n')
            if res.get('banner'):
                f.write(f'  服务横幅：{res["banner"]}\n')
            if res['credentials']:
                for user, pwd in res['credentials']:
                    if res['service'] == 'redis' and not user:
                        f.write(f'  [弱口令] 无认证 / {pwd if pwd else "空密码"}\n')
                    else:
                        f.write(f'  [弱口令] {user}/{pwd}\n')
            else:
                f.write('  [弱口令] 未检出\n')
            f.write('\n')


def save_summary(output_path, stats, start_time, end_time, results):
    if not output_path:
        return
    with open(output_path, 'a', encoding='utf-8') as f:
        f.write('========================================\n')
        f.write('              扫描统计\n')
        f.write('========================================\n')
        f.write(f'开始时间：{start_time.strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write(f'结束时间：{end_time.strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write(f'开放服务：{stats["open"]}\n')
        f.write(f'弱口令数：{stats["weak"]}\n')
        if results:
            f.write('\n[开放服务汇总]\n')
            for r in results:
                def fmt_cred(u, p):
                    if r['service'] == 'redis':
                        if not p:
                            return '无认证'
                        return p
                    return f'{u}/{p}' if u else f'空/{p}'
                creds = ', '.join([fmt_cred(u, p) for u, p in r['credentials']]) or '无'
                f.write(f'  {r["service"].upper()} {r["ip"]}:{r["port"]} -> 弱口令：{creds}\n')
        f.write('========================================\n')


def connect_redis(ip, port, password, timeout=10):
    """扫描完成后，对 Redis 进行简单的交互式连接。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if password:
            s.send(f'AUTH {password}\r\n'.encode())
            resp = s.recv(1024)
            if not resp.startswith(b'+OK'):
                print('[!] Redis 认证失败，无法连接。')
                s.close()
                return
        print(f'[*] 已连接到 Redis {ip}:{port}')
        print('[*] 提示：输入命令后按回车执行，例如 INFO、KEYS *、GET key')
        print('[*] 输入 exit、quit 或 q 退出连接。')
        while True:
            try:
                cmd = input('redis> ').strip()
                if cmd.lower() in ('exit', 'quit', 'q'):
                    break
                if not cmd:
                    continue
                s.send((cmd + '\r\n').encode())
                resp = s.recv(4096)
                print(resp.decode('utf-8', 'replace').strip())
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f'[!] 执行出错：{e}')
                break
        s.close()
        print('[*] 已断开 Redis 连接。')
    except Exception as e:
        print(f'[!] 连接失败：{e}')


def interactive_connect(results):
    """扫描完成后，让用户选择连接哪个存在弱口令的服务。"""
    weak_results = []
    for r in results:
        for user, pwd in r['credentials']:
            weak_results.append({
                'service': r['service'],
                'ip': r['ip'],
                'port': r['port'],
                'user': user,
                'pwd': pwd,
            })

    if not weak_results:
        print('[*] 没有发现弱口令，无需连接。')
        return

    print('\n[*] 发现以下存在弱口令的服务，可以选择连接：')
    for i, item in enumerate(weak_results, 1):
        if item['service'] == 'redis':
            cred = '无认证' if not item['pwd'] else f'密码：{item["pwd"]}'
        else:
            cred = f'{item["user"]}/{item["pwd"]}'
        print(f'  {i}. {item["service"].upper()} {item["ip"]}:{item["port"]} -> {cred}')

    try:
        choice = input('\n请输入编号连接（直接回车取消）：').strip()
        if not choice:
            return
        idx = int(choice) - 1
        if idx < 0 or idx >= len(weak_results):
            print('[!] 编号无效。')
            return
        item = weak_results[idx]
        svc = item['service']
        ip = item['ip']
        port = item['port']
        user = item['user']
        pwd = item['pwd']

        if svc == 'redis':
            connect_redis(ip, port, pwd)
        elif svc == 'mysql':
            print(f'[*] 请使用以下命令连接 MySQL：')
            print(f'    mysql -h {ip} -P {port} -u {user} -p{pwd}')
        elif svc == 'ssh':
            print(f'[*] 请使用以下命令连接 SSH：')
            print(f'    ssh -p {port} {user}@{ip}')
        elif svc == 'rdp':
            print(f'[*] 请使用以下命令连接 RDP：')
            print(f'    xfreerdp /v:{ip}:{port} /u:{user} /p:{pwd}')
        else:
            print('[!] 暂不支持该服务的自动连接。')
    except ValueError:
        print('[!] 请输入有效的数字编号。')
    except Exception as e:
        print(f'[!] 连接选择失败：{e}')


def signal_handler(signum, frame):
    print('\n[!] 收到中断信号，正在停止扫描...')
    STOP_FLAG.set()


def main():
    parser = argparse.ArgumentParser(
        description='网络服务探测与弱口令检测工具：扫描 SSH/RDP/MySQL/Redis 服务并尝试常见弱口令。',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例：
  python3 scanner.py -t 192.168.1.0/24
  python3 scanner.py -t 10.0.0.0/8 --sample 10 --threads 200 --rate 500
  python3 scanner.py -t 192.168.1.1 --only ssh --ssh-port 2222
  python3 scanner.py -t 172.16.0.0/16 --proxy socks5://127.0.0.1:1080
  python3 scanner.py -t 192.168.1.0/24 --no-brute -o results.txt
        '''
    )
    parser.add_argument('-t', '--target', required=True,
                        help='目标 IP 或 CIDR（支持 /8、/16、/24）')
    parser.add_argument('--only', choices=['ssh', 'rdp', 'mysql', 'redis'],
                        help='只扫描指定服务')
    parser.add_argument('--ssh-port', type=int, default=DEFAULT_PORTS['ssh'],
                        help='SSH 端口（默认 22）')
    parser.add_argument('--rdp-port', type=int, default=DEFAULT_PORTS['rdp'],
                        help='RDP 端口（默认 3389）')
    parser.add_argument('--mysql-port', type=int, default=DEFAULT_PORTS['mysql'],
                        help='MySQL 端口（默认 3306）')
    parser.add_argument('--redis-port', type=int, default=DEFAULT_PORTS['redis'],
                        help='Redis 端口（默认 6379）')
    parser.add_argument('--threads', type=int, default=50,
                        help='最大并发线程数（默认 50）')
    parser.add_argument('--timeout', type=int, default=3,
                        help='连接超时时间，单位秒（默认 3）')
    parser.add_argument('--rate', type=int, default=100,
                        help='每秒最大连接数（默认 100）')
    parser.add_argument('--proxy',
                        help='代理地址，支持 socks5://host:port 或 http://host:port')
    parser.add_argument('--sample', type=int,
                        help='每个 /24 子网随机采样 N 个主机（对 /8、/16 很有用）')
    parser.add_argument('--max-hosts', type=int,
                        help='最多扫描的主机数量')
    parser.add_argument('--full', action='store_true',
                        help='强制全量扫描大网段（默认 /8、/16 会自动按 /24 采样）')
    parser.add_argument('--user-dict',
                        help='自定义用户名字典文件（格式：服务名:用户名，每行一个）')
    parser.add_argument('--pass-dict',
                        help='自定义密码字典文件（格式：服务名:密码，每行一个）')
    parser.add_argument('--no-brute', action='store_true',
                        help='跳过弱口令尝试，只探测端口')
    parser.add_argument('-o', '--output',
                        help='结果保存文件（覆盖写入，包含详细结果和统计）')
    parser.add_argument('--connect', action='store_true',
                        help='扫描结束后，对发现弱口令的服务进行交互式连接（目前支持 Redis）')
    parser.add_argument('--dry-run', action='store_true',
                        help='只统计目标数量，不实际扫描')

    args = parser.parse_args()

    # 彻底抑制第三方库日志输出
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    setup_proxy(args.proxy)

    services = ['ssh', 'rdp', 'mysql', 'redis']
    if args.only:
        services = [args.only]

    ports = {
        'ssh': args.ssh_port,
        'rdp': args.rdp_port,
        'mysql': args.mysql_port,
        'redis': args.redis_port,
    }

    # 加载自定义字典
    user_dict = parse_service_dict(args.user_dict)
    pass_dict = parse_service_dict(args.pass_dict)
    args.user_dict_data = user_dict if user_dict else DEFAULT_USER_DICT
    args.pass_dict_data = pass_dict if pass_dict else DEFAULT_PASS_DICT

    warn_large_network(args.target)

    estimated = estimate_tasks(args.target, len(services), args.sample, args.max_hosts, args.full)

    if args.dry_run:
        print(f'[*] 演练模式：预计扫描 {estimated} 个任务（{estimated // len(services)} 主机 × {len(services)} 服务）。')
        return

    # 初始化输出文件
    init_output(args.output, args.target, services)

    print(f'[*] 开始扫描：预计 {estimated} 个任务（约 {estimated // len(services)} 主机 × {len(services)} 服务）')
    print(f'[*] 线程数：{args.threads}，超时：{args.timeout} 秒，速率：{args.rate}/秒')
    if args.proxy:
        print(f'[*] 代理：{args.proxy}')
    if args.output:
        print(f'[*] 结果将保存到：{args.output}')
    if args.no_brute:
        print('[*] 已禁用弱口令尝试')

    start_time = datetime.now()
    limiter = TokenBucket(args.rate)
    results = []
    output_lock = threading.Lock()
    print_lock = threading.Lock()
    stats_lock = threading.Lock()
    stats = {'done': 0, 'open': 0, 'weak': 0}
    last_progress = [time.time()]

    def worker(task):
        if STOP_FLAG.is_set():
            return None
        try:
            res = scan_task(args, *task, limiter)
            with stats_lock:
                stats['done'] += 1
                if res:
                    stats['open'] += 1
                    stats['weak'] += len(res['credentials'])
                    print_result(res, print_lock)
                    save_result(res, args.output, output_lock)
                    results.append(res)
            # 每 5 秒打印一次进度
            now = time.time()
            if now - last_progress[0] >= 5:
                with stats_lock:
                    print(f'[*] 进度：已完成 {stats["done"]}/{estimated}，发现开放 {stats["open"]}，弱口令 {stats["weak"]}')
                last_progress[0] = now
            return res
        except Exception as e:
            with stats_lock:
                stats['done'] += 1
            return None

    tasks = generate_tasks(args.target, services, ports, args.sample, args.max_hosts, args.full)

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = set()
            for task in tasks:
                if STOP_FLAG.is_set():
                    break
                future = executor.submit(worker, task)
                futures.add(future)
                # 限制未完成任务数量，防止内存无限增长
                if len(futures) >= args.threads * 2:
                    done, futures = wait(futures, return_when=FIRST_COMPLETED)
                    for f in done:
                        f.result()

            for f in as_completed(futures):
                if STOP_FLAG.is_set():
                    break
                f.result()
    except KeyboardInterrupt:
        print('\n[!] 用户按下 Ctrl+C，正在停止...')
        STOP_FLAG.set()

    end_time = datetime.now()
    save_summary(args.output, stats, start_time, end_time, results)

    print(f'[*] 扫描结束。发现 {stats["open"]} 个开放服务，{stats["weak"]} 组弱口令。')
    if args.output:
        print(f'[*] 详细结果已保存：{args.output}')

    if args.connect and not STOP_FLAG.is_set():
        interactive_connect(results)


if __name__ == '__main__':
    main()
