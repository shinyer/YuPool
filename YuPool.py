#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
proxy_pool.py
- fetch:  从多个来源抓取代理并分类保存
- check:  并发验证代理可用性并输出 alive/dead/stats
- all:    fetch + check

Linux 终端友好，适合放 GitHub。
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp

# =============== 可选：SOCKS 支持（需要 aiohttp_socks） ===============
try:
    from aiohttp_socks import ProxyConnector  # type: ignore
    SOCKS_SUPPORTED = True
except Exception:
    ProxyConnector = None
    SOCKS_SUPPORTED = False


# ===================== 代理源（已合并：hq.py + xdl.py） =====================
_RAW_SOURCES = [
    # hq.py
    {"name": "TheSpeedX/PROXY-List", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
     "parser": "text", "protocol": "socks5"},
    {"name": "hookzof/socks5_list", "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
     "parser": "text", "protocol": "socks5"},
    {"name": "ProxyScraper/ProxyScraper", "url": "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
     "parser": "text", "protocol": "socks5"},
    {"name": "proxifly/free-proxy-list",
     "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
     "parser": "text", "protocol": "http"},
    {"name": "zloi-user/hideip.me", "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks5.txt",
     "parser": "text", "protocol": "socks5"},
    {"name": "gfpcom/free-proxy-list", "url": "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/socks5.txt",
     "parser": "text", "protocol": "socks5"},
    {"name": "monosans/proxy-list", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json",
     "parser": "json-list", "protocol": "socks5"},
    {"name": "fate0/proxylist", "url": "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list",
     "parser": "json-lines", "protocol": "http"},

    # xdl.py 里重复的 URL 会自动去重
    {"name": "ProxyScraper/ProxyScraper (SOCKS5)", "url": "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
     "parser": "text", "protocol": "socks5"},
]

# URL 去重
_seen_urls = set()
SOURCES: List[Dict[str, str]] = []
for s in _RAW_SOURCES:
    if s["url"] not in _seen_urls:
        _seen_urls.add(s["url"])
        SOURCES.append(s)

# =============== 解析辅助（兼容你 hq.py 的逻辑） ===============
RE_SCHEME_PROXY = re.compile(
    r'\b(?P<scheme>https?|socks4|socks5)://(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{2,5})\b',
    re.IGNORECASE
)
RE_IP_PORT = re.compile(r'\b(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{2,5})\b')


def _is_valid_ip_port(host: str, port: str) -> bool:
    try:
        parts = host.split(".")
        if len(parts) != 4:
            return False
        if any(not (0 <= int(p) <= 255) for p in parts):
            return False
        p = int(port)
        return 1 <= p <= 65535
    except Exception:
        return False


def clean_proxy_line(line: str) -> Optional[str]:
    """
    清理并格式化单行代理数据，只返回 "ip:port"（或域名:port）形式
    """
    line = (line or "").strip()
    if not line:
        return None

    # 去协议头、认证
    if "//" in line:
        line = line.split("//", 1)[-1]
    if "@" in line:
        line = line.split("@", 1)[-1]

    # 去多余字段：ip:port:xx -> ip:port
    parts = line.split(":")
    if len(parts) > 2:
        line = f"{parts[0]}:{parts[1]}"

    if ":" not in line:
        return None
    host, port = line.split(":", 1)
    host = host.strip()
    port = port.strip()

    # host 可以是域名，这里不强校验；但如果是 IP 则校验
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host):
        if not _is_valid_ip_port(host, port):
            return None

    if not port.isdigit():
        return None
    p = int(port)
    if p < 1 or p > 65535:
        return None

    return f"{host}:{port}"


def deduce_protocol(original_line: str, default_protocol: str) -> str:
    """
    智能协议推断（保持你 hq.py 的习惯）：
    - socks4 优先
    - socks5 / socks
    - http
    - 否则 default_protocol
    """
    s = (original_line or "").lower()
    if "socks4" in s:
        return "socks4"
    if "socks5" in s or "socks" in s:
        return "socks5"
    if "http" in s:
        return "http"
    return (default_protocol or "http").lower()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_lines(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for x in lines:
            f.write(x + "\n")


def read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [x.strip() for x in f if x.strip()]


# ===================== FETCH（抓取） =====================
async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int) -> str:
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
        resp.raise_for_status()
        return await resp.text(errors="ignore")


def extract_proxies_from_text(content: str, default_protocol: str) -> Tuple[Set[str], Set[str], Set[str]]:
    """
    从文本中抽取代理，并分类为 http / socks5 / socks4（带 scheme://）
    """
    http_set: Set[str] = set()
    s5_set: Set[str] = set()
    s4_set: Set[str] = set()

    if not content:
        return http_set, s5_set, s4_set

    for line in content.splitlines():
        if not line.strip():
            continue

        # 1) 行内如果带 scheme:// 优先识别
        m = RE_SCHEME_PROXY.search(line)
        if m:
            scheme = m.group("scheme").lower()
            host = m.group("host")
            port = m.group("port")
            if _is_valid_ip_port(host, port):
                addr = f"{host}:{port}"
                if scheme in ("http", "https"):
                    http_set.add(f"http://{addr}")
                elif scheme == "socks5":
                    s5_set.add(f"socks5://{addr}")
                elif scheme == "socks4":
                    s4_set.add(f"socks4://{addr}")
            continue

        # 2) 否则按你 hq.py 的“智能推断 + 清理”
        proto = deduce_protocol(line, default_protocol)
        cleaned = clean_proxy_line(line)
        if not cleaned:
            continue

        if proto == "http":
            http_set.add(f"http://{cleaned}")
        elif proto == "socks5":
            s5_set.add(f"socks5://{cleaned}")
        elif proto == "socks4":
            s4_set.add(f"socks4://{cleaned}")

    return http_set, s5_set, s4_set


def extract_proxies_from_fate0_jsonlines(content: str, default_protocol: str) -> Tuple[Set[str], Set[str], Set[str]]:
    http_set: Set[str] = set()
    s5_set: Set[str] = set()
    s4_set: Set[str] = set()

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = obj.get("host")
        port = obj.get("port")
        if not host or not port:
            continue

        cleaned = clean_proxy_line(f"{host}:{port}")
        if not cleaned:
            continue

        proxy_type = (obj.get("type", default_protocol) or default_protocol).lower()
        if "http" in proxy_type:
            http_set.add(f"http://{cleaned}")
        elif "socks4" in proxy_type:
            s4_set.add(f"socks4://{cleaned}")
        elif "socks5" in proxy_type or "socks" in proxy_type:
            s5_set.add(f"socks5://{cleaned}")

    return http_set, s5_set, s4_set


async def cmd_fetch(args: argparse.Namespace) -> int:
    out_dir = args.out
    ensure_dir(out_dir)

    http_set: Set[str] = set()
    s5_set: Set[str] = set()
    s4_set: Set[str] = set()

    meta = {
        "ts": int(time.time()),
        "sources_total": len(SOURCES),
        "sources": [],
    }

    headers = {"User-Agent": "proxy-pool/1.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        for idx, src in enumerate(SOURCES, 1):
            name = src["name"]
            url = src["url"]
            parser = src["parser"]
            default_proto = src["protocol"]

            print(f"[*] ({idx}/{len(SOURCES)}) fetch: {name}")
            try:
                text = await fetch_text(session, url, timeout=args.timeout)

                before = (len(http_set), len(s5_set), len(s4_set))

                if parser in ("text", "json-list"):
                    h, s5, s4 = extract_proxies_from_text(text, default_proto)
                elif parser == "json-lines":
                    h, s5, s4 = extract_proxies_from_fate0_jsonlines(text, default_proto)
                else:
                    h, s5, s4 = set(), set(), set()

                http_set |= h
                s5_set |= s5
                s4_set |= s4

                after = (len(http_set), len(s5_set), len(s4_set))
                added = {"http": after[0] - before[0], "socks5": after[1] - before[1], "socks4": after[2] - before[2]}

                meta["sources"].append({"name": name, "url": url, "ok": True, "added": added})
                print(f"[+] added: http={added['http']} socks5={added['socks5']} socks4={added['socks4']}")
            except Exception as e:
                meta["sources"].append({"name": name, "url": url, "ok": False, "error": str(e)})
                print(f"[!] failed: {e}")

            if args.sleep > 0:
                await asyncio.sleep(args.sleep)

    # 写候选文件
    candidates_http = os.path.join(out_dir, "candidates_http.txt")
    candidates_s5 = os.path.join(out_dir, "candidates_socks5.txt")
    candidates_s4 = os.path.join(out_dir, "candidates_socks4.txt")
    fetch_meta = os.path.join(out_dir, "fetch_meta.json")

    write_lines(candidates_http, sorted(http_set))
    write_lines(candidates_s5, sorted(s5_set))
    write_lines(candidates_s4, sorted(s4_set))

    meta["unique"] = {"http": len(http_set), "socks5": len(s5_set), "socks4": len(s4_set)}
    with open(fetch_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print("\n[OK] fetch done")
    print(f" - {candidates_http} ({len(http_set)})")
    print(f" - {candidates_s5} ({len(s5_set)})")
    print(f" - {candidates_s4} ({len(s4_set)})")
    print(f" - {fetch_meta}")
    return 0


# ===================== CHECK（验证） =====================
async def probe_http(session: aiohttp.ClientSession, proxy: str, url: str) -> Tuple[bool, float, str]:
    t0 = time.perf_counter()
    try:
        async with session.get(url, proxy=proxy) as resp:
            if resp.status != 200:
                return False, 0.0, f"status={resp.status}"
            await resp.text()
        return True, time.perf_counter() - t0, "ok"
    except Exception as e:
        return False, 0.0, str(e)


async def probe_socks(proxy: str, url: str, timeout_sec: int) -> Tuple[bool, float, str]:
    if not SOCKS_SUPPORTED:
        return False, 0.0, "aiohttp_socks not installed"

    t0 = time.perf_counter()
    try:
        connector = ProxyConnector.from_url(proxy)  # type: ignore
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "proxy-pool/1.0"},
        ) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return False, 0.0, f"status={resp.status}"
                await resp.text()
        return True, time.perf_counter() - t0, "ok"
    except Exception as e:
        return False, 0.0, str(e)


async def check_one(proxy: str, sem: asyncio.Semaphore, session: aiohttp.ClientSession,
                    test_url_http: str, test_url_https: str, timeout_sec: int, retry: int) -> Tuple[str, bool, float, str]:
    scheme = (urlparse(proxy).scheme or "http").lower()

    # http 用 http 测试更宽松；其他用 https 更严格
    url = test_url_http if scheme == "http" else test_url_https

    async with sem:
        last_err = "unknown"
        for _ in range(retry + 1):
            if scheme in ("http", "https"):
                ok, cost, msg = await probe_http(session, proxy, url)
            elif scheme in ("socks5", "socks4"):
                ok, cost, msg = await probe_socks(proxy, url, timeout_sec)
            else:
                return proxy, False, 0.0, f"unsupported scheme={scheme}"

            if ok:
                return proxy, True, cost, msg
            last_err = msg

        return proxy, False, 0.0, last_err


async def cmd_check(args: argparse.Namespace) -> int:
    out_dir = args.out
    ensure_dir(out_dir)

    http_list = read_lines(os.path.join(out_dir, "candidates_http.txt"))
    s5_list = read_lines(os.path.join(out_dir, "candidates_socks5.txt"))
    s4_list = read_lines(os.path.join(out_dir, "candidates_socks4.txt"))

    all_list = http_list + s5_list + s4_list
    if not all_list:
        print("[!] no candidates found. run fetch first.")
        return 2

    sem = asyncio.Semaphore(args.concurrency)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    headers = {"User-Agent": "proxy-pool/1.0"}

    alive_http: List[Tuple[str, float]] = []
    alive_s5: List[Tuple[str, float]] = []
    alive_s4: List[Tuple[str, float]] = []
    dead: List[Tuple[str, str]] = []

    t_start = time.time()

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        tasks = [
            check_one(
                p, sem, session,
                test_url_http=args.test_http,
                test_url_https=args.test_https,
                timeout_sec=args.timeout,
                retry=args.retry
            )
            for p in all_list
        ]

        done = 0
        total = len(tasks)
        for coro in asyncio.as_completed(tasks):
            proxy, ok, cost, msg = await coro
            done += 1
            if args.quiet is False and done % max(1, total // 20) == 0:
                print(f"[*] progress: {done}/{total}")

            if ok:
                scheme = urlparse(proxy).scheme.lower()
                if scheme in ("http", "https"):
                    alive_http.append((proxy, cost))
                elif scheme == "socks5":
                    alive_s5.append((proxy, cost))
                elif scheme == "socks4":
                    alive_s4.append((proxy, cost))
            else:
                dead.append((proxy, msg))

    alive_http.sort(key=lambda x: x[1])
    alive_s5.sort(key=lambda x: x[1])
    alive_s4.sort(key=lambda x: x[1])

    def dump_alive(pairs: List[Tuple[str, float]], path: str) -> None:
        write_lines(path, [f"{p}\t{cost:.3f}s" for p, cost in pairs])

    dump_alive(alive_http, os.path.join(out_dir, "alive_http.txt"))
    dump_alive(alive_s5, os.path.join(out_dir, "alive_socks5.txt"))
    dump_alive(alive_s4, os.path.join(out_dir, "alive_socks4.txt"))
    write_lines(os.path.join(out_dir, "dead.txt"), [f"{p}\t{err}" for p, err in dead])

    stats = {
        "ts": int(time.time()),
        "total": len(all_list),
        "alive_http": len(alive_http),
        "alive_socks5": len(alive_s5),
        "alive_socks4": len(alive_s4),
        "dead": len(dead),
        "success_rate": round((len(alive_http) + len(alive_s5) + len(alive_s4)) / max(1, len(all_list)), 4),
        "duration_sec": round(time.time() - t_start, 3),
        "timeout_seconds": args.timeout,
        "concurrency": args.concurrency,
        "retry": args.retry,
        "socks_support": SOCKS_SUPPORTED,
        "test_http": args.test_http,
        "test_https": args.test_https,
    }

    with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print("\n[OK] check done")
    print(f" - alive_http:   {len(alive_http)} -> {os.path.join(out_dir, 'alive_http.txt')}")
    print(f" - alive_socks5: {len(alive_s5)} -> {os.path.join(out_dir, 'alive_socks5.txt')}")
    print(f" - alive_socks4: {len(alive_s4)} -> {os.path.join(out_dir, 'alive_socks4.txt')}")
    print(f" - dead:         {len(dead)} -> {os.path.join(out_dir, 'dead.txt')}")
    print(f" - stats:              -> {os.path.join(out_dir, 'stats.json')}")
    if not SOCKS_SUPPORTED:
        print("提示：要检测 socks4/socks5，请安装：pip install aiohttp_socks")
    return 0


# ===================== ALL（fetch + check） =====================
async def cmd_all(args: argparse.Namespace) -> int:
    r1 = await cmd_fetch(args)
    if r1 != 0:
        return r1
    return await cmd_check(args)


# ===================== CLI =====================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="proxy_pool",
        description="Single-file Proxy Fetcher & Checker (Linux-friendly, GitHub-ready)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("-o", "--out", default="./data", help="输出目录（默认：./data）")
        sp.add_argument("--timeout", type=int, default=15, help="请求/检测超时秒数（默认：15）")
        sp.add_argument("--sleep", type=float, default=0.0, help="每个源之间睡眠秒数（默认：0）")

    # fetch
    sp_fetch = sub.add_parser("fetch", help="抓取代理并保存候选文件")
    add_common(sp_fetch)

    # check
    sp_check = sub.add_parser("check", help="验证候选代理并输出可用列表")
    add_common(sp_check)
    sp_check.add_argument("-c", "--concurrency", type=int, default=120, help="并发数（默认：120）")
    sp_check.add_argument("--retry", type=int, default=1, help="失败重试次数（默认：1）")
    sp_check.add_argument("--test-http", default="http://httpbin.org/ip", help="HTTP 检测 URL")
    sp_check.add_argument("--test-https", default="https://httpbin.org/ip", help="HTTPS/SOCKS 检测 URL")
    sp_check.add_argument("--quiet", action="store_true", help="减少进度输出")

    # all
    sp_all = sub.add_parser("all", help="先抓取再验证（一次完成）")
    add_common(sp_all)
    sp_all.add_argument("-c", "--concurrency", type=int, default=120, help="并发数（默认：120）")
    sp_all.add_argument("--retry", type=int, default=1, help="失败重试次数（默认：1）")
    sp_all.add_argument("--test-http", default="http://httpbin.org/ip", help="HTTP 检测 URL")
    sp_all.add_argument("--test-https", default="https://httpbin.org/ip", help="HTTPS/SOCKS 检测 URL")
    sp_all.add_argument("--quiet", action="store_true", help="减少进度输出")

    return p


async def main_async() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "fetch":
        return await cmd_fetch(args)
    if args.cmd == "check":
        return await cmd_check(args)
    if args.cmd == "all":
        return await cmd_all(args)

    return 1


def main() -> None:
    try:
        rc = asyncio.run(main_async())
        raise SystemExit(rc)
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
