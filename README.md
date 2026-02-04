# YuPool (Single-file Proxy Fetcher & Checker)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20(Kali%2FUbuntu%2FDebian)-success)
![License](https://img.shields.io/badge/License-MIT-informational)

A Linux‑friendly, **single‑file** CLI tool to **fetch** public proxy candidates from multiple sources and **check** their availability concurrently.

> **Use responsibly.** This repository is intended for network learning, connectivity verification, and **authorized** testing only. Do not use it to access systems you don’t own or have explicit permission to test.

---

## ✨ Features

- **Single file**: `yupool.py`
- **CLI subcommands**:
  - `fetch` — pull and normalize candidates from multiple sources
  - `check` — verify proxies concurrently and export results
  - `all` — run `fetch` then `check`
- **Protocols**
  - HTTP/HTTPS (built-in)
  - SOCKS5 / SOCKS4 (optional via `aiohttp_socks`)
- **Normalization & de-dup**
  - Accepts `ip:port`, `http(s)://ip:port`, `socks(4/5)://ip:port`
  - Strips auth/userinfo and extra fields when present
  - Deduplicates across sources
- **Operational outputs**
  - Candidates by protocol
  - Alive lists with latency
  - Dead list with error reasons
  - JSON metadata and stats

---

## 📦 Project Layout (Recommended)

```
.
├── yupool.py
├── README.md
├── requirements.txt
└── .gitignore
```

**requirements.txt**
```txt
aiohttp
aiohttp_socks
```

**.gitignore**
```gitignore
.venv/
__pycache__/
data/
*.pyc
```

---

## ✅ Requirements

- Linux (Kali / Ubuntu / Debian recommended)
- Python **3.9+** (3.10/3.11 recommended)

---

## 🚀 Installation

### Option A — Virtualenv (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Option B — System install (not recommended)

```bash
pip3 install aiohttp aiohttp_socks
```

---

## 🧰 Usage

Make the script executable:

```bash
chmod +x yupool.py
```

### 1) Fetch only

```bash
./yupool.py fetch -o ./data
```

### 2) Check only

```bash
./yupool.py check -o ./data -c 200 --timeout 8 --retry 1
```

### 3) Run everything

```bash
./yupool.py all -o ./data -c 200 --timeout 8 --retry 1 --quiet
```

---

## ⚙️ Command Reference

### `fetch`

```bash
./yupool.py fetch \
  -o ./data \
  --timeout 15 \
  --sleep 0
```

**Options**
- `-o, --out` output directory (default: `./data`)
- `--timeout` per-source fetch timeout in seconds (default: `15`)
- `--sleep` sleep seconds between sources (default: `0`)

---

### `check`

```bash
./yupool.py check \
  -o ./data \
  -c 200 \
  --timeout 8 \
  --retry 1 \
  --test-http  "http://httpbin.org/ip" \
  --test-https "https://httpbin.org/ip" \
  --quiet
```

**Options**
- `-o, --out` output directory (default: `./data`)
- `-c, --concurrency` number of concurrent checks (default: `120`)
- `--timeout` per-proxy check timeout in seconds (default: `15`)
- `--retry` retry count for failed probes (default: `1`)
- `--test-http` URL used for HTTP checks (default: `http://httpbin.org/ip`)
- `--test-https` URL used for HTTPS/SOCKS checks (default: `https://httpbin.org/ip`)
- `--quiet` reduce progress output

> **Tip (stability):** Replace `--test-http/--test-https` with a URL you control (e.g., `https://yourdomain.tld/health`) to reduce false negatives caused by public endpoints.

---

## 🗂 Output Files

All files are written under the output directory (default: `./data/`).

### After `fetch`

- `candidates_http.txt`  
  `http://ip:port`
- `candidates_socks5.txt`  
  `socks5://ip:port`
- `candidates_socks4.txt`  
  `socks4://ip:port`
- `fetch_meta.json`  
  Per-source fetch result + counts (useful for debugging blocked sources)

### After `check`

- `alive_http.txt`  
  `proxy<TAB>latency` (e.g., `http://1.2.3.4:8080\t0.532s`)
- `alive_socks5.txt`  
  `proxy<TAB>latency`
- `alive_socks4.txt`  
  `proxy<TAB>latency`
- `dead.txt`  
  `proxy<TAB>error_reason` (timeout/refused/ssl/etc.)
- `stats.json`  
  Summary: totals, success rate, duration, concurrency, socks support, test URLs

---

## 🔧 Tuning Guide (Kali/Ubuntu)

Recommended starting points:

- **Fast scan**
  - `-c 250 --timeout 6 --retry 0`
- **Balanced**
  - `-c 200 --timeout 8 --retry 1`
- **More tolerant (unstable networks)**
  - `-c 120 --timeout 12 --retry 2`

If you see lots of timeouts:
- lower concurrency (`-c 80~150`)
- increase timeout (`--timeout 10~12`)
- use a closer/faster test URL (preferably your own)

---

## 🧩 SOCKS Support

SOCKS4/SOCKS5 checks require:

```bash
pip install aiohttp_socks
```

If not installed, the tool still runs but SOCKS checks will be reported as unsupported.

---

## 🛡 Security Notes

- Public proxies are **untrusted**. Assume they can:
  - log traffic
  - inject/modify content
  - break TLS expectations (MITM attempts)
- Do not use public proxies for credentials, payments, or sensitive data.
- Prefer your own test endpoints and avoid testing against third‑party services.

---

## 🧪 Troubleshooting

**1) `aiohttp_socks not installed`**
- Install: `pip install aiohttp_socks`

**2) Very low success rate**
- Normal for public proxies.
- Try:
  - Use your own `--test-http/--test-https`
  - Increase `--timeout`
  - Reduce concurrency

**3) Some sources fail**
- GitHub raw/CDN sources may rate-limit.
- Re-run with `--sleep 0.2` and/or lower fetch timeout.
- Check `fetch_meta.json` for per-source errors.

---

## 🤝 Contributing

Pull requests are welcome. Please:
1. Keep changes in **single-file** style unless there’s a clear benefit.
2. Preserve Linux-first CLI behavior.
3. Avoid adding features that enable misuse.

---

## 📄 License

MIT (recommended). Add a `LICENSE` file to the repository root.

---

## Disclaimer

This tool is provided “as is”, without warranty. You are responsible for ensuring lawful and authorized use.
